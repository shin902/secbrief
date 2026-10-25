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

    def make_asar(self, path, files):
        payload=b""; tree={"files":{}}
        for loc, data in files.items():
            node=tree["files"]
            parts=loc.split("/")
            for part in parts[:-1]: node=node.setdefault(part,{"files":{}})["files"]
            node[parts[-1]]={"size":len(data),"offset":str(len(payload))}; payload+=data
        js=json.dumps(tree,separators=(",",":")).encode(); padded=js+b"\0"*(-len(js)%4)
        header=struct.pack("<II",4+len(padded),len(js))+padded
        path.write_bytes(struct.pack("<II",4,len(header))+header+payload)

    def test_asar_scoped_nested_packages_and_osv_assets(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"app.asar"
            self.make_asar(p,{"app/package.json":b'{"name":"app","version":"1"}',"app/node_modules/@scope/a/package.json":b'{"name":"@scope/a","version":"2.3"}',"app/node_modules/a/node_modules/b/package.json":b'{"name":"b","version":"3"}'})
            assets=s.inspect_asar(p)["assets"]
            self.assertEqual({(x["name"],x["version"]) for x in assets},{("app","1"),("@scope/a","2.3"),("b","3")})
            seen=[]
            def fake(url,body=None,timeout=30):
                if url.endswith("querybatch"):
                    seen.extend(q["package"]["name"] for q in body["queries"]); return {"results":[{} for q in body["queries"]]}
                raise AssertionError(url)
            s.osv_scan(assets,fake); self.assertEqual(set(seen),{"app","@scope/a","b"})

    def test_directory_scan_skips_symlink_and_lists_native_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"app.asar.unpacked"; (root/"node_modules/@scope/pkg").mkdir(parents=True)
            (root/"node_modules/@scope/pkg/package.json").write_text('{"name":"@scope/pkg","version":"1.2"}')
            (root/"addon.node").write_bytes(b"not a real library")
            outside=Path(d)/"outside"; outside.mkdir(); (outside/"package.json").write_text('{"name":"bad","version":"9"}')
            (root/"escape").symlink_to(outside,target_is_directory=True)
            scan=s.inspect_app_directory(root)
            self.assertEqual([a["name"] for a in scan["assets"]],["@scope/pkg"])
            self.assertEqual(scan["native_libraries"][0]["path"],"addon.node")

    def test_runtime_opt_in_fuse_gate_and_observed_versions(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as d:
            binary=Path(d)/"electron"; binary.write_bytes(b"binary"+s.FUSE_SENTINEL+bytes([1,1])+b"1"+b"end")
            with patch.object(s.subprocess,"run") as run:
                self.assertEqual(s.inspect_runtime(binary)["run_as_node_fuse"],"enabled")
                run.assert_called_once()
                run.return_value=Mock(returncode=0,stdout='{"electron":"33","node":"20","chrome":"130","v8":"13","brotli":"1","openssl":"3"}')
                result=s.inspect_runtime(binary)
                self.assertEqual(result["versions"]["node"]["value"],"20")
            disabled=Path(d)/"disabled"; disabled.write_bytes(s.FUSE_SENTINEL+bytes([1,1])+b"0")
            with patch.object(s.subprocess,"run") as run:
                result=s.inspect_runtime(disabled); run.assert_not_called(); self.assertEqual(result["run_as_node_fuse"],"disabled")

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
