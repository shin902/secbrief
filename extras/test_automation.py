import contextlib, io, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import automation as a


def cycle_result(config):
    output=io.StringIO()
    with contextlib.redirect_stdout(output):
        code=a.cycle(config)
    return code,json.loads(output.getvalue())


class AutomationTests(unittest.TestCase):
    def test_cycle_returns_changed_nochange_and_failed_json_status(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); out=root/'out'; state=root/'state'; out.mkdir()
            config=root/'config.json'; config.write_text(json.dumps({"schema":"secbrief-automation/config-v1","runner":"unused","output":str(out),"state_dir":str(state)}))
            (out/'report.json').write_text('{}')
            report={"status":"complete","change_count":1}
            with patch.object(a,"load_config",return_value=json.loads(config.read_text())), patch.object(a,"run_runner",return_value=type("P",(),{"returncode":10,"stdout":"","stderr":""})()), patch.object(a,"strict_json",return_value=report):
                code,result=cycle_result(config)
            self.assertEqual(code,0); self.assertEqual(result['status'],'changed')
            report={"status":"complete","change_count":0}
            with patch.object(a,"load_config",return_value=json.loads(config.read_text())), patch.object(a,"run_runner",return_value=type("P",(),{"returncode":0,"stdout":"","stderr":""})()), patch.object(a,"strict_json",return_value=report):
                code,result=cycle_result(config)
            self.assertEqual(code,0); self.assertEqual(result['status'],'nochange')
            with patch.object(a,"load_config",return_value=json.loads(config.read_text())), patch.object(a,"run_runner",return_value=type("P",(),{"returncode":2,"stdout":"","stderr":"scan failed"})()), patch.object(a,"strict_json",return_value=report):
                code,result=cycle_result(config)
            self.assertEqual(code,2); self.assertEqual(result['status'],'failed')
            self.assertFalse((state/'outbox.jsonl').exists())
            self.assertFalse((state/'receipts.jsonl').exists())

    def test_plan_requires_exact_hash_and_runs_harmless_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); target=root/'value.txt'; planfile=root/'repair.json'; config=root/'config.json'
            update=[sys.executable,'-c',"from pathlib import Path; Path('value.txt').write_text('v2')"]
            verify=[sys.executable,'-c',"import json; from pathlib import Path; p=Path('value.txt'); print(json.dumps({'version':p.read_text(),'status':'ready'}))"]
            cfg={"schema":"secbrief-automation/config-v1","runner":"unused","output":str(root/'out'),"state_dir":str(root/'state'),"env_allowlist":[],"remediation_plans":{"fixture":{"cwd":d,"update":update,"verify":{"argv":verify,"expected_json":{"version":"v2","status":"ready"}},"readiness":[{"argv":[sys.executable,'-c',"print('READY')"],"expected_stdout":"READY\n"}]}}}
            config.write_text(json.dumps(cfg)); target.write_text('v1')
            data=a.plan_data(a.load_config(config),'fixture'); data['plan_hash']=a.digest(data); planfile.write_text(json.dumps(data))
            with self.assertRaisesRegex(a.AutomationError,'approval denied'):
                a.execute_plan(planfile,'')
            self.assertEqual(target.read_text(),'v1')
            data['update'][2] += ";# tampered"; planfile.write_text(json.dumps(data))
            with self.assertRaisesRegex(a.AutomationError,'hash mismatch'):
                a.execute_plan(planfile,data['plan_hash'])
            data=a.plan_data(a.load_config(config),'fixture'); data['plan_hash']=a.digest(data); planfile.write_text(json.dumps(data))
            self.assertEqual(a.execute_plan(planfile,data['plan_hash']),0)
            receipt=json.loads((root/'.secbrief-remediation-receipt.json').read_text())
            self.assertEqual(receipt['status'],'verified'); self.assertEqual(target.read_text(),'v2')
            self.assertEqual(oct((root/'.secbrief-remediation-receipt.json').stat().st_mode & 0o777),'0o600')

    def test_verify_mismatch_never_claims_success(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); cfg={"schema":"secbrief-automation/config-v1","runner":"unused","output":str(root),"state_dir":str(root/'state'),"remediation_plans":{"bad":{"cwd":d,"update":[sys.executable,'-c','pass'],"verify":{"argv":[sys.executable,'-c',"print('{\\\"version\\\":\\\"wrong\\\",\\\"status\\\":\\\"ready\\\"}')"],"expected_json":{"version":"wanted","status":"ready"}}}}}
            cp=root/'config.json'; cp.write_text(json.dumps(cfg)); plan=a.plan_data(a.load_config(cp),'bad'); plan['plan_hash']=a.digest(plan); pp=root/'plan.json'; pp.write_text(json.dumps(plan))
            self.assertEqual(a.execute_plan(pp,plan['plan_hash']),2)
            receipt=json.loads((root/'.secbrief-remediation-receipt.json').read_text()); self.assertEqual(receipt['status'],'failed')


class IntegrationTests(unittest.TestCase):
    def test_source_changes_are_reported_and_timestamp_only_is_silent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); out=root/'out'; out.mkdir(); state=root/'state'
            src=root/'sources.json'; src.write_text('{}')
            cp=root/'config.json'; cp.write_text(json.dumps({'schema':'secbrief-automation/config-v1','runner':'unused','output':str(out),'state_dir':str(state),'inventory_sources_config':str(src)}))
            source={'assets':[],'errors':[],'advisories':[],'source_snapshots':[{'source_url':'https://vendor.test/feed','sha256':'one','retrieved_at':'first'}]}
            def runner(c):
                (out/'report.json').write_text(json.dumps({'status':'inventory_only','change_count':None})); (out/'report.md').write_text('# test\n')
                return subprocess.CompletedProcess([],0,'','')
            with patch.object(a,'run_runner',side_effect=runner), patch('inventory_sources.collect',return_value=source):
                code,result=cycle_result(cp); self.assertEqual(code,0); self.assertEqual(result['status'],'nochange')
                source['source_snapshots'][0]['retrieved_at']='second'
                code,result=cycle_result(cp); self.assertEqual(code,0); self.assertEqual(result['status'],'nochange')
                source['source_snapshots'][0]['sha256']='two'
                code,result=cycle_result(cp); self.assertEqual(code,0); self.assertTrue(result['source_changed'])
                self.assertEqual(result['status'],'changed')
                source['errors']=['source failed']
                code,result=cycle_result(cp); self.assertEqual(code,2); self.assertEqual(result['status'],'failed')
                self.assertEqual(json.loads((state/'source-state.json').read_text())['sources'][0]['sha256'],'two')

    def test_restart_precedes_verification_and_approval_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as d:
            cp=Path(d)/'config.json'; pp=Path(d)/'plan.json'
            cfg={'schema':'secbrief-automation/config-v1','runner':'unused','output':d,'state_dir':d,'remediation_plans':{'repair':{'cwd':d,'update':[sys.executable,'-c',"from pathlib import Path; Path('phase').write_text('updated')"],'restart':[sys.executable,'-c',"from pathlib import Path; Path('phase').write_text('restarted')"],'verify':{'argv':[sys.executable,'-c',"import json; from pathlib import Path; print(json.dumps({'version':'2','status':Path('phase').read_text()}))"],'expected_json':{'version':'2','status':'restarted'}}}}}
            cp.write_text(json.dumps(cfg)); plan=a.plan_data(a.load_config(cp),'repair'); plan['plan_hash']=a.digest(plan); pp.write_text(json.dumps(plan))
            self.assertEqual(a.execute_plan(pp,plan['plan_hash']),0)
            with self.assertRaisesRegex(a.AutomationError,'already attempted'): a.execute_plan(pp,plan['plan_hash'])

    def test_agent_export_never_executes_arbitrary_command(self):
        with tempfile.TemporaryDirectory() as d:
            cp=Path(d)/'config.json'; (Path(d)/'report.json').write_text('{}')
            cp.write_text(json.dumps({'schema':'secbrief-automation/config-v1','runner':'unused','output':d,'state_dir':d}))
            with patch.object(a.subprocess,'run') as run:
                self.assertEqual(a.agent_plan(cp,Path(d)/'request.json'),0)
                with self.assertRaises(a.AutomationError): a.agent_plan(cp,Path(d)/'request.json',['malicious'])
                run.assert_not_called()

if __name__=='__main__': unittest.main()
