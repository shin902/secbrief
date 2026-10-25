import json, struct, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import secbrief_extra as s

class ToolkitTests(unittest.TestCase):
    def test_inventory_npm_composer_and_exact_identity(self):
        with tempfile.TemporaryDirectory() as d:
            npm=Path(d)/"package-lock.json"; comp=Path(d)/"composer.lock"
            npm.write_text(json.dumps({"lockfileVersion":3,"packages":{"":{"name":"root","version":"1"},"node_modules/@acme/lib":{"version":"2.1.0"}}}))
            comp.write_text(json.dumps({"packages":[{"name":"acme/lib","version":"v1.2"}],"packages-dev":[]}))
            assets, errors=s.inventory([str(npm),str(comp)])
            self.assertEqual(errors,[]); self.assertEqual([(a["ecosystem"],a["name"],a["version"]) for a in assets],[("npm","@acme/lib","2.1.0"),("Packagist","acme/lib","v1.2")])
            self.assertEqual(assets[0]["source"],str(npm))

    def test_asar_static_metadata_and_no_execution(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"app.asar"
            tree={"files":{"package.json":{"size":len(b'{"version":"4.5.6","engines":{"node":">=18"}}'),"offset":"0"}}}
            js=json.dumps(tree,separators=(",",":")).encode()
            padded = js + b"\0" * (-len(js) % 4)
            header = struct.pack("<II", 4 + len(padded), len(js)) + padded
            p.write_bytes(struct.pack("<II", 4, len(header)) + header + b'{"version":"4.5.6","engines":{"node":">=18"}}')
            result=s.inspect_asar(p)
            self.assertEqual(result["installed_version"],"4.5.6"); self.assertIsNone(result["electron"]); self.assertIsNone(result["node"])

    def test_asar_rejects_oversized_header(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"bad.asar"; p.write_bytes(struct.pack("<II",s.MAX_ASAR_HEADER+9,s.MAX_ASAR_HEADER+1))
            with self.assertRaises(s.ScanError): s.inspect_asar(p)

    def test_osv_detail_and_failure_are_not_safe(self):
        assets=[{"ecosystem":"npm","name":"pkg","version":"1","source":"lock","location":"node_modules/pkg"}]
        calls=[]
        def fake(url, body=None, timeout=30):
            calls.append(url)
            if url.endswith("querybatch"): return {"results":[{"vulns":[{"id":"GHSA-test"}]}]}
            return {"id":"GHSA-test","affected":[{"package":{"name":"pkg","ecosystem":"npm"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}
        findings, errors=s.osv_scan(assets, fake)
        self.assertFalse(errors); self.assertEqual(calls,[s.OSV+"/querybatch",s.OSV+"/vulns/GHSA-test"])
        self.assertEqual(findings[0]["status"],"affected (OSV exact-version match)"); self.assertEqual(findings[0]["fixed_versions"],["2.0"])
        failed, errors=s.osv_scan(assets, lambda *a,**k: (_ for _ in ()).throw(OSError("offline")))
        self.assertTrue(errors); self.assertEqual(failed[0]["status"],"unknown")

    def test_handoff_requires_approval_and_does_not_execute(self):
        with tempfile.TemporaryDirectory() as d:
            report=Path(d)/"report.json"; out=Path(d)/"handoff.json"
            report.write_text(json.dumps({"findings":[{"asset":{"name":"x","version":"1"},"status":"unknown","advisory_id":"OSV-1","url":"https://osv.dev/x"}]}))
            s.handoff(report,out); hand=json.loads(out.read_text())
            self.assertTrue(hand["approval_required"]); self.assertIn("Do not execute",hand["tasks"][0]["instructions"])

    def test_successful_diff_baseline_and_change_exit_codes(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            args=SimpleNamespace(output=d,lockfile=[],asar=[],online=True)
            with patch.object(s,"osv_scan",return_value=([],[])), patch.object(s,"kev_lookup",return_value=(True,None)):
                self.assertEqual(s.run(args),0)
            item={"asset":{"name":"pkg","version":"1","source":"lock","location":"node_modules/pkg"},"advisory_id":"GHSA-1","status":"affected","kev":False,"fixed_versions":[],"url":"https://osv.dev/vulnerability/GHSA-1"}
            with patch.object(s,"osv_scan",return_value=([item.copy()],[])), patch.object(s,"kev_lookup",return_value=(True,None)):
                self.assertEqual(s.run(args),10)
            with patch.object(s,"osv_scan",return_value=([item.copy()],[])), patch.object(s,"kev_lookup",return_value=(True,None)):
                self.assertEqual(s.run(args),0)
            report=json.loads((Path(d)/"report.json").read_text())
            self.assertEqual(report["change_count"],0)
            self.assertEqual(json.loads((Path(d)/"alerts.json").read_text())["changed"],[])

    def test_removed_finding_is_change_not_proof_of_fix(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            args = SimpleNamespace(output=d, lockfile=[], asar=[], online=True)
            (Path(d)/"state.json").write_text(json.dumps({"baseline": True, "findings": {"old": {}}}))
            with patch.object(s, "osv_scan", return_value=([], [])), patch.object(s, "kev_lookup", return_value=(True, None)):
                self.assertEqual(s.run(args), 10)
            self.assertEqual(json.loads((Path(d)/"alerts.json").read_text())["changed"], ["old"])

    def test_paginated_osv_is_incomplete(self):
        asset = {"name": "demo", "ecosystem": "npm", "version": "1"}
        findings, errors = s.osv_scan([asset], lambda *a: {"results": [{"next_page_token": "more"}]})
        self.assertTrue(errors)
        self.assertEqual(findings[0]["status"], "unknown")

    def test_inventory_only_and_degraded_runs_never_advance_state(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/"state.json"; state.write_text('{"baseline":true,"findings":{"old":{}}}')
            from types import SimpleNamespace
            args=SimpleNamespace(output=d,lockfile=[],asar=[],online=False)
            self.assertEqual(s.run(args),0); self.assertEqual(json.loads(state.read_text())["findings"],{"old":{}})
            args.online=True
            with patch.object(s,"osv_scan",return_value=([],["failed"])), patch.object(s,"kev_lookup",return_value=(False,"failed")):
                self.assertEqual(s.run(args),2); self.assertEqual(json.loads(state.read_text())["findings"],{"old":{}})

if __name__ == "__main__": unittest.main()
