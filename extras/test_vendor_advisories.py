import unittest

from vendor_advisories import map_advisories, _range_match


class VendorAdvisoryTests(unittest.TestCase):
    def snapshot(self, repo, record, url=None):
        return {"source_url": url or f"https://api.github.com/repos/{repo}/security-advisories",
                "retrieved_at": "2026-10-25T00:00:00Z", "sha256": "abc123", "document": [record]}

    def record(self, name="bun", ecosystem="npm", version_range=">= 1.3.14, < 1.4.4"):
        return {"ghsa_id": "GHSA-test-0000-0000", "cve_id": "CVE-2026-1234",
                "identifiers": [{"type": "CVE", "value": "CVE-2026-1234"}],
                "vulnerabilities": [{"package": {"ecosystem": ecosystem, "name": name},
                                     "vulnerable_version_range": version_range,
                                     "first_patched_version": "1.4.4"}]}

    def test_maps_repo_bound_runtime_and_returns_existing_advisory_shape(self):
        asset = {"ecosystem": "bun-runtime", "name": "bun", "version": "1.4.0",
                 "location": "/opt/bun"}
        findings, errors = map_advisories([asset], [self.snapshot("oven-sh/bun", self.record())])
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        row = findings[0]
        self.assertEqual(row["assessment"], "affected")
        self.assertEqual(row["installed"], "affected")
        self.assertEqual(row["fixed_versions"], ["1.4.4"])
        self.assertEqual(row["cve_ids"], ["CVE-2026-1234"])
        self.assertEqual(row["evidence"][0]["source_sha256"], "abc123")
        self.assertEqual(row["vendor_release_available"], "unknown")

    def test_supported_unaffected_and_unsupported_syntax_are_explicit(self):
        asset = {"ecosystem": "node-runtime", "name": "node", "version": "22.0.0"}
        snapshot = self.snapshot("nodejs/node", self.record("node", version_range=">=20.0.0, <21.0.0"))
        findings, errors = map_advisories([asset], [snapshot])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["assessment"], "not_affected")
        snapshot["document"][0]["vulnerabilities"][0]["vulnerable_version_range"] = "^20.0.0"
        findings, errors = map_advisories([asset], [snapshot])
        self.assertEqual(findings[0]["assessment"], "not_affected")
        self.assertEqual(_range_match("20.0.1", ">=20.0.0 <20.3.0 || >=21.1.0, <21.2.0"), True)
        self.assertIsNone(_range_match("20.0.1", "~20.0"))
        self.assertTrue(_range_match("20.0.1", "^20.0.0"))

    def test_origin_binding_rejects_lookalike_host_and_unapproved_repo(self):
        for repo, url in (("evil/nodejs-node", "https://api.github.com/repos/evil/nodejs-node/security-advisories"),
                          ("nodejs/node", "https://api.github.com.attacker.invalid/repos/nodejs/node/security-advisories")):
            findings, errors = map_advisories([], [self.snapshot(repo, self.record(), url)])
            self.assertEqual(findings, [])
            self.assertTrue(errors)

    def test_electron_assets_do_not_match_upstream_node_advisory(self):
        electron = {"ecosystem": "electron", "name": "electron", "version": "40.0.0",
                    "location": "/app/node_modules/electron"}
        findings, errors = map_advisories([electron], [self.snapshot("nodejs/node", self.record("node"))])
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

    def test_php_real_package_shape_and_branch_scoped_fix(self):
        php = {"ecosystem": "php-runtime", "name": "php", "version": "8.2.20"}
        record = self.record("php-src", "php", "<8.5.11")
        record["vulnerabilities"][0]["first_patched_version"] = {"identifier": "8.5.11"}
        findings, errors = map_advisories([php], [self.snapshot("php/php-src", record)])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["assessment"], "unknown")
        self.assertEqual(findings[0]["fixed_versions"], [])

    def test_php_extension_is_candidate_but_not_definitive(self):
        php = {"ecosystem": "php-runtime", "name": "php", "version": "8.2.20"}
        record = self.record("ext-standard", "php", "<8.3.1")
        findings, errors = map_advisories([php], [self.snapshot("php/php-src", record)])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["assessment"], "unknown")
        self.assertEqual(findings[0]["component_candidate"], "ext-standard")
        self.assertEqual(findings[0]["component_condition"], "extension applicability unknown")

    def test_empty_snapshot_withdrawn_and_unrelated_records(self):
        empty = self.snapshot("oven-sh/bun", None)
        empty["document"] = []
        unrelated = self.snapshot("oven-sh/bun", {"metadata": "not an advisory"})
        withdrawn = self.record()
        withdrawn["withdrawn_at"] = "2026-01-01T00:00:00Z"
        asset = {"ecosystem": "bun-runtime", "name": "bun", "version": "1.4.0"}
        findings, errors = map_advisories([asset], [empty, unrelated, self.snapshot("oven-sh/bun", withdrawn)])
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

    def test_node_core_index_ranges_and_patched_precedence(self):
        url = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
        asset = {"ecosystem": "node-runtime", "name": "node", "version": "20.5.0"}
        raw = {"_record_id": "NODE-TEST", "ref": "https://example.invalid/advisory",
               "cve": ["CVE-2026-2222"], "vulnerable": "^20.0.0",
               "patched": ">=20.5.0 <21.0.0"}
        snapshot = self.snapshot("nodejs/node", None, url)
        snapshot["document"] = {"node_core": [raw]}
        findings, errors = map_advisories([asset], [snapshot])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["assessment"], "not_affected")
        self.assertEqual(findings[0]["advisory_id"], "https://example.invalid/advisory")
        self.assertEqual(findings[0]["cve_ids"], ["CVE-2026-2222"])

    def test_node_and_electron_fixes_do_not_cross_major_branches(self):
        node = {"ecosystem": "node-runtime", "name": "node", "version": "22.4.0"}
        node_record = self.record("node", "npm", "<23.0.0")
        node_record["vulnerabilities"][0]["first_patched_version"] = "23.1.0"
        findings, errors = map_advisories([node], [self.snapshot("nodejs/node", node_record)])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["assessment"], "unknown")

        electron = {"ecosystem": "electron", "name": "electron", "version": "39.2.0"}
        electron_record = self.record("electron", "npm", "<40.1.0")
        electron_record["vulnerabilities"][0]["first_patched_version"] = "40.1.0"
        findings, errors = map_advisories([electron], [self.snapshot("electron/electron", electron_record)])
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["assessment"], "unknown")

    def test_caret_wildcards_zero_semver_and_fixed_version_validation(self):
        self.assertTrue(_range_match("0.2.9", "^0.2.3"))
        self.assertFalse(_range_match("0.3.0", "^0.2.3"))
        self.assertTrue(_range_match("20.7.1", "20.x"))
        self.assertFalse(_range_match("21.0.0", "20.x"))
        asset = {"ecosystem": "bun-runtime", "name": "bun", "version": "1.4.0"}
        record = self.record()
        record["vulnerabilities"][0]["first_patched_version"] = "released soon"
        findings, errors = map_advisories([asset], [self.snapshot("oven-sh/bun", record)])
        self.assertEqual(errors, [])
        self.assertEqual(findings[0]["fixed_versions"], [])


if __name__ == "__main__":
    unittest.main()
