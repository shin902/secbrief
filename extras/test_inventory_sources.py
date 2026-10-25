import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import inventory_sources as s


class InventorySourceTests(unittest.TestCase):
    def test_collect_is_offline_and_does_not_execute_runtime_without_consent(self):
        with patch.object(s, "_run", side_effect=AssertionError("unexpected execution")):
            result = s.collect({"runtime_paths": {"node": ["/opt/node"], "php": "/opt/php"},
                                "python_env_paths": [], "os_package_managers": {}})
        self.assertEqual([(r["runtime"], r["executable"], r["status"]) for r in result["runtimes"]],
                         [("node", "/opt/node", "not_probed"), ("php", "/opt/php", "not_probed")])
        self.assertFalse(result["coverage"]["network_enabled"])
        self.assertEqual(result["containers"]["status"], "not_configured")

    def test_runtime_probes_only_configured_absolute_executables(self):
        def run(path, args, **kwargs):
            self.assertTrue(Path(path).is_absolute())
            return "v22.1.0\n"
        with patch.object(s, "_run", side_effect=run):
            result = s.collect({"runtime_paths": {"node": "/custom/node", "bun": "/custom/bun"}}, True)
        self.assertEqual([r["version"] for r in result["runtimes"]], ["22.1.0", "22.1.0"])
        with patch.object(s, "_run") as run:
            s.collect({"runtime_paths": {"node": "node"}}, True)
            run.assert_called_once()
        # The configured relative path is rejected before subprocess invocation.
        with patch.object(s.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                s._run("node", ["--version"])
            run.assert_not_called()

    def test_pip_inventory_preserves_environment_and_does_not_export_env_values(self):
        with patch.object(s, "_run", return_value='[{"name":"demo","version":"1.0"}]') as run:
            result = s.collect({"python_env_paths": ["/srv/app/venv"], "runtime_paths": {}})
        self.assertEqual(result["assets"][0]["environment"], "/srv/app/venv")
        self.assertEqual(result["assets"][0]["version"], "1.0")
        self.assertEqual(str(run.call_args.args[0]), "/srv/app/venv/bin/python")
        self.assertNotIn("environment_variables", result)

    def test_os_inventory_parsing(self):
        with patch.object(s, "_run", return_value="libx:amd64\t1.2\tamd64\n"):
            result = s.collect({"os_package_managers": {"dpkg": "/usr/bin/dpkg-query"}})
        self.assertEqual(result["assets"][0]["name"], "libx:amd64")
        self.assertEqual(result["assets"][0]["architecture"], "amd64")
        self.assertEqual(result["coverage"]["os"]["dpkg"]["status"], "observed")

    def test_configured_container_inventory_and_opt_in_exec_probes(self):
        def run(path, args, **kwargs):
            if args[:1] == ["ps"]:
                return '{"ID":"abc123","Image":"demo:1","Names":"demo","Status":"Up"}\n'
            if args[:2] == ["image", "ls"]:
                return '{"ID":"sha256:1","Repository":"demo","Tag":"1","Digest":"sha256:1"}\n'
            self.assertEqual(args[:3], ["exec", "abc123", "node"])
            return "v20.0.0\n"
        config = {"docker_path": "/usr/bin/docker", "container_probes": ["node"]}
        with patch.object(s, "_run", side_effect=run) as invoke:
            no_probe = s.collect(config)
            self.assertEqual(invoke.call_count, 2)
        with patch.object(s, "_run", side_effect=run):
            probed = s.collect(config, probe_runtimes=True)
        self.assertEqual(no_probe["containers"]["running"][0]["id"], "abc123")
        self.assertEqual(probed["containers"]["probes"][0]["output"], "v20.0.0")

    def test_fetch_records_timestamp_digest_and_rejects_non_https(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _size): return b'{"id":"GHSA-test"}'
            def geturl(self): return "https://vendor.example/advisory.json"
        with patch.object(s.urllib.request, "urlopen", return_value=Response()):
            snapshot = s._fetch_json("https://vendor.example/advisory.json")
        self.assertEqual(snapshot["sha256"], hashlib.sha256(b'{"id":"GHSA-test"}').hexdigest())
        self.assertTrue(snapshot["retrieved_at"])
        with self.assertRaises(ValueError):
            s._fetch_json("http://example.org/feed")

    def test_reviewed_rule_requires_matching_hash_and_exact_evidence(self):
        snapshot = {"source_url": "https://vendor.example/a.json", "sha256": "abc",
                    "retrieved_at": "now", "document": [{"id": "GHSA-1", "summary": "fixed in 2.0"}]}
        asset = {"ecosystem": "npm", "name": "pkg", "version": "1.0"}
        rule = {"source_url": snapshot["source_url"], "source_sha256": "abc", "advisory_id": "GHSA-1",
                "ecosystem": "npm", "package": "pkg", "affected_versions": ["1.0"],
                "upstream_fixed_versions": ["2.0"], "vendor_fixed_versions": [],
                "evidence_text": "fixed in 2.0"}
        errors = []
        found = s._reviewed_findings([asset], [snapshot], [rule], errors)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["upstream_fixed"], "yes")
        self.assertEqual(found[0]["vendor_fixed_versions"], [])
        self.assertEqual(found[0]["vendor_release_available"], "unknown")
        rule["source_sha256"] = "stale"
        errors = []
        self.assertEqual(s._reviewed_findings([asset], [snapshot], [rule], errors), [])
        self.assertIn("hash mismatch", errors[0]["error"])

    def test_php_runtime_asset_matches_exact_rule_and_requires_fixed_version_proof(self):
        def run(path, args, **kwargs): return "PHP 8.4.1 (cli)\n"
        with patch.object(s, "_run", side_effect=run):
            result = s.collect({"runtime_paths": {"php": "/opt/php/bin/php"}}, True)
        asset = next(a for a in result["assets"] if a["ecosystem"] == "php-runtime")
        self.assertEqual((asset["name"], asset["version"], asset["runtime_path"]),
                         ("php", "8.4.1", "/opt/php/bin/php"))
        doc = {"ghsa_id": "GHSA-php-test", "summary": "PHP fixed in 8.4.2"}
        snap = {"source_url": "https://vendor.example/a", "sha256": "hash", "retrieved_at": "now", "document": doc}
        rule = {"source_url": snap["source_url"], "source_sha256": "hash", "advisory_id": "GHSA-php-test",
                "ecosystem": "php-runtime", "package": "php", "runtime_path": "/opt/php/bin/php",
                "affected_versions": ["8.4.1"], "upstream_fixed_versions": ["8.4.2"],
                "vendor_fixed_versions": [], "evidence_text": "PHP fixed in 8.4.2"}
        found = s._reviewed_findings([asset], [snap], [rule], [])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["fixed_versions"], ["8.4.2"])
        self.assertEqual(found[0]["installed_asset_name"], "php")
        self.assertIsNone(found[0]["running_asset_name"])
        rule["runtime_path"] = "/other/php"
        self.assertEqual(s._reviewed_findings([asset], [snap], [rule], []), [])
        rule["runtime_path"] = "/opt/php/bin/php"
        rule["upstream_fixed_versions"] = ["8.4.9"]
        found = s._reviewed_findings([asset], [snap], [rule], [])
        self.assertEqual(found[0]["fixed_versions"], [])
        self.assertEqual(found[0]["upstream_fixed"], "unknown")

    def test_container_runtime_and_electron_are_normalized_assets_with_locations(self):
        def run(path, args, **kwargs):
            if args[:1] == ["ps"]: return '{"ID":"cid","Image":"demo","Names":"demo","Status":"Up"}\n'
            if args[:2] == ["image", "ls"]: return ""
            return "PHP 8.3.4 (cli)\n"
        config = {"docker_path": "/usr/bin/docker", "container_probes": ["php"],
                  "installed_assets": [{"ecosystem": "electron", "name": "electron", "version": "31.2.0",
                                        "location": "/app/node_modules/electron"}]}
        with patch.object(s, "_run", side_effect=run):
            result = s.collect(config, probe_runtimes=True)
        container = next(a for a in result["assets"] if a["source"] == "container:cid")
        electron = next(a for a in result["assets"] if a["ecosystem"] == "electron")
        self.assertEqual((container["version"], container["runtime_path"]), ("8.3.4", "container:cid"))
        self.assertEqual(electron["location"], "/app/node_modules/electron")

    def test_osv_malformed_and_paged_responses_are_errors_not_clean(self):
        asset = {"ecosystem": "npm", "name": "demo", "version": "1.0.0"}
        for payload in (b'{"vulns":{}}', b'{"vulns":[],"next_page_token":"more"}'):
            class Response:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def read(self, _size): return payload
            with patch.object(s.urllib.request, "urlopen", return_value=Response()):
                errors = []
                rows = s._check_osv([asset], errors)
            self.assertTrue(errors)
            self.assertEqual(rows[0]["upstream_fixed"], "unknown")

    def test_atom_and_electron_release_array_parsers(self):
        raw = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>x</id><title>Node fix</title><summary>Fixed 22.1.0</summary><link href="https://nodejs.org/x"/></entry></feed>'
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _size): return raw
        with patch.object(s.urllib.request, "urlopen", return_value=Response()):
            snap = s._fetch_source("https://nodejs.org/en/feed/blog.xml", "atom")
        self.assertEqual(snap["document"]["items"][0]["description"], "Fixed 22.1.0")
        releases = [{"version": "40.3.10", "stable": True}, {"version": "41.0.0-beta.1"},
                    {"version": "40.4.0", "stable": True}]
        snap = {"source_url": "https://releases.electronjs.org/releases.json", "retrieved_at": "now",
                "sha256": "x", "document": releases}
        rows = s._release_drift([{"ecosystem": "electron", "name": "electron", "version": "40.3.10"}],
                               [snap], snap["source_url"])
        self.assertEqual(rows[0]["latest_release"], "40.4.0")
        self.assertEqual(rows[0]["security_fixed"], "unknown")

    def test_osv_exact_query_contains_supported_ecosystems_and_unknown_on_failure(self):
        asset = {"ecosystem": "PyPI", "name": "demo", "version": "1.0", "source": "/venv"}
        self.assertEqual(s._osv_asset(asset)["package"]["ecosystem"], "PyPI")
        with patch.object(s.urllib.request, "urlopen", side_effect=OSError("offline")):
            errors = []
            rows = s._check_osv([asset], errors)
        self.assertEqual(rows[0]["advisory_id"], None)
        self.assertEqual(rows[0]["upstream_fixed"], "unknown")
        self.assertTrue(errors)

    def test_electron_latest_release_drift_is_not_cve_proof(self):
        assets = [{"ecosystem": "electron", "name": "electron", "version": "31.0.0"}]
        snap = {"source_url": "https://example/electron", "retrieved_at": "now", "sha256": "x",
                "document": {"tag_name": "v33.0.0"}}
        self.assertEqual(s._release_drift(assets, [snap], "https://example/electron")[0]["latest_release"], "33.0.0")
        snap["document"] = {"latest": "33.0.0"}
        rows = s._release_drift(assets, [snap], "https://example/electron")
        self.assertTrue(rows[0]["drift"])
        self.assertEqual(rows[0]["security_fixed"], "unknown")

    def test_rss_snapshot_keeps_exact_advisory_text_for_review_mapping(self):
        raw = b'<rss><channel><item><guid>node-1</guid><title>Security release</title><description>Node.js 20.1.0 fixes CVE-2025-1234</description><link>https://nodejs.org/security</link></item></channel></rss>'
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, _size): return raw
        with patch.object(s.urllib.request, "urlopen", return_value=Response()):
            snap = s._fetch_source("https://nodejs.org/security.xml", "rss")
        rule = {"source_url": snap["source_url"], "source_sha256": snap["sha256"], "advisory_id": "node-1",
                "ecosystem": "npm", "package": "node", "affected_versions": ["20.0.0"],
                "upstream_fixed_versions": ["20.1.0"], "evidence_text": "Node.js 20.1.0 fixes CVE-2025-1234"}
        rows = s._reviewed_findings([{"ecosystem": "npm", "name": "node", "version": "20.0.0"}], [snap], [rule], [])
        self.assertEqual(rows[0]["cve_ids"], [])
        self.assertIn("CVE-2025-1234", rows[0]["evidence"][0]["text"])

    def test_real_read_only_host_package_inventory_when_available(self):
        pacman = Path("/usr/bin/pacman")
        if not pacman.exists():
            self.skipTest("pacman is not installed")
        result = s.collect({"os_package_managers": {"pacman": str(pacman)}})
        self.assertEqual(result["coverage"]["os"]["pacman"]["status"], "observed")
        self.assertGreater(result["coverage"]["os"]["pacman"]["packages"], 0)
        # Do not print local package names or versions from this host-level check.


if __name__ == "__main__":
    unittest.main()
