"""Deterministic upstream advisory mapping for inventoried components.

API: map_advisories(assets, snapshots) -> (findings, errors). Snapshots use
inventory_sources' source_url/retrieved_at/sha256/document schema. Only
repository-bound components are compared; bundled Electron Node is not inferred.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_REPOS = {
    "nodejs/node": ("node-runtime", "node", "npm"),
    "php/php-src": ("php-runtime", "php", "php"),
    "electron/electron": ("electron", "electron", "npm"),
    "oven-sh/bun": ("bun-runtime", "bun", "npm"),
}
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_COMPARATOR = re.compile(r"^(>=|<=|>|<|=)?(\d+\.\d+\.\d+)$")
_FIXED = re.compile(r"^\d+\.\d+\.\d+$")


def _version(value):
    match = _VERSION.fullmatch(value) if isinstance(value, str) else None
    return tuple(map(int, match.groups())) if match else None


def _range_match(version, expression):
    """True/False for supported comparator clauses, None for unknown syntax."""
    installed = _version(version)
    if installed is None or not isinstance(expression, str) or not expression.strip():
        return None
    branches = expression.split("||")
    for branch in branches:
        terms = re.split(r"[\s,]+", branch.strip())
        if not terms or any(not term for term in terms):
            return None
        normalized = []
        index = 0
        while index < len(terms):
            if terms[index] in (">", ">=", "<", "<=", "=") and index + 1 < len(terms):
                normalized.append(terms[index] + terms[index + 1])
                index += 2
            else:
                normalized.append(terms[index])
                index += 1
        comparisons = []
        for term in normalized:
            match = _COMPARATOR.fullmatch(term)
            if match:
                op, raw = match.groups()
                target = _version(raw)
            else:
                # npm caret ranges use semver's special 0.x upper bounds.
                caret = re.fullmatch(r"\^(\d+)\.(\d+)\.(\d+)", term)
                if caret:
                    major, minor, patch = map(int, caret.groups())
                    target = (major, minor, patch)
                    upper = ((major + 1, 0, 0) if major else
                             (0, minor + 1, 0) if minor else (0, 0, patch + 1))
                    comparisons.append(installed >= target and installed < upper)
                    continue
                # x/* components are expanded to a half-open version interval.
                wildcard = re.fullmatch(r"(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?", term)
                if wildcard and any(part in (None, "x", "X", "*") for part in wildcard.groups()):
                    parts = wildcard.groups()
                    prefix = []
                    for part in parts:
                        if part is None or part in ("x", "X", "*"):
                            break
                        prefix.append(int(part))
                    if not prefix:
                        comparisons.append(True)
                        continue
                    low = tuple(prefix + [0] * (3 - len(prefix)))
                    hi = list(low)
                    hi[len(prefix) - 1] += 1
                    hi[len(prefix):] = [0] * (3 - len(prefix))
                    comparisons.append(low <= installed < tuple(hi))
                    continue
                return None
            if target is None:
                return None
            op = op or "="
            comparisons.append({">": installed > target, ">=": installed >= target,
                                "<": installed < target, "<=": installed <= target,
                                "=": installed == target}[op])
        if all(comparisons):
            return True
    return False


def _records(document):
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        if isinstance(document.get("node_core"), list):
            return document["node_core"]
        for key in ("advisories", "data"):
            if isinstance(document.get(key), list):
                return document[key]
        if document.get("ghsa_id") or document.get("id"):
            return [document]
    return []


def _cves(advisory):
    values = [advisory.get("cve_id")]
    identifiers = advisory.get("identifiers", [])
    if isinstance(identifiers, list):
        values.extend(i.get("value") for i in identifiers if isinstance(i, dict) and i.get("type") == "CVE")
    return sorted({v for v in values if isinstance(v, str) and v.startswith("CVE-")})


def _repo_url(url):
    if not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "api.github.com" or
            parsed.username or parsed.password or parsed.port not in (None, 443)):
        return None
    match = re.fullmatch(r"/repos/([^/]+/[^/]+)/security-advisories(?:/[^/]+)?/?", parsed.path)
    if not match:
        return None
    return match.group(1).lower()


def _snapshot_repo(url):
    repo = _repo_url(url)
    if repo:
        return repo
    if url in (
        "https://codeload.github.com/nodejs/security-wg/zip/refs/heads/main",
        "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json",
    ):
        return "nodejs/node"
    return None


def _fixed_version(vuln):
    value = vuln.get("first_patched_version")
    if isinstance(value, dict):
        value = value.get("identifier")
    if isinstance(value, str) and _FIXED.fullmatch(value):
        return value
    patched = vuln.get("patched_versions")
    if isinstance(patched, str) and _FIXED.fullmatch(patched.strip()):
        return patched.strip()
    if isinstance(patched, str):
        lower_bounds = re.findall(r"(?:^|[\s,])>=\s*(\d+\.\d+\.\d+)(?=$|[\s,])", patched)
        if len(lower_bounds) == 1:
            return lower_bounds[0]
    return None


def map_advisories(assets, snapshots):
    """Return findings and errors; unsupported syntax is unknown, never safe."""
    findings, errors = [], []
    for snapshot in snapshots:
        url = snapshot.get("source_url") if isinstance(snapshot, dict) else None
        repo = _snapshot_repo(url)
        if repo not in _REPOS:
            if repo in ('python/cpython','google/brotli') or not isinstance(url,str) or 'security-advisories' not in url:
                continue
            errors.append({"source": str(url), "error": "not an allowed GitHub repository advisory URL"})
            continue
        ecosystem, name, runtime_ecosystem = _REPOS[repo]
        try:
            digest = snapshot["sha256"]
            retrieved = snapshot["retrieved_at"]
            records = _records(snapshot["document"])
            if not isinstance(digest, str) or not digest or not isinstance(retrieved, str) or not retrieved:
                raise ValueError("snapshot provenance is incomplete")
            # An empty repository response is a valid, current snapshot.
        except (KeyError, TypeError, ValueError) as exc:
            errors.append({"source": str(url), "error": str(exc)})
            continue
        for advisory in records:
            if not isinstance(advisory, dict):
                errors.append({"source": str(url), "error": "advisory record is not an object"})
                continue
            if advisory.get("withdrawn_at") or advisory.get("withdrawn"):
                continue
            node_raw = repo == "nodejs/node" and "vulnerable" in advisory and "patched" in advisory
            vulnerabilities = advisory.get("vulnerabilities")
            if node_raw:
                vulnerabilities = [{"package": {"ecosystem": "npm", "name": "node"},
                                    "vulnerable_version_range": advisory.get("vulnerable"),
                                    "patched_versions": advisory.get("patched")}]
            if node_raw and not isinstance(vulnerabilities, list):
                continue
            if not isinstance(vulnerabilities, list):
                # Non-advisory records from a mixed upstream snapshot are irrelevant.
                continue
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                package = vuln.get("package") or {}
                php_candidate = (repo == "php/php-src" and isinstance(package, dict) and
                                 package.get("ecosystem") == "php" and
                                 isinstance(package.get("name"), str) and
                                 (package["name"] == "php-src" or package["name"].startswith("ext-")))
                php_extension = php_candidate and package["name"].startswith("ext-")
                expected = (isinstance(package, dict) and package.get("name") == name and
                            package.get("ecosystem") == runtime_ecosystem)
                if not (expected or php_candidate):
                    continue
                for asset in assets:
                    compatible = asset.get('ecosystem') == ecosystem or (repo=='electron/electron' and asset.get('ecosystem')=='npm')
                    if not compatible or asset.get("name") != name:
                        continue
                    vulnerable = vuln.get("vulnerable_version_range")
                    matched = _range_match(asset["version"], vulnerable)
                    patched_range = vuln.get("patched_versions")
                    patched_match = _range_match(asset["version"], patched_range) if isinstance(patched_range, str) else None
                    fix = _fixed_version(vuln)
                    if node_raw and isinstance(patched_range,str):
                        installed_tuple=_version(asset.get('version'))
                        bounds=[]
                        for clause in patched_range.split('||'):
                            m=re.match(r'^\s*(?:\^|>=|=)?\s*(\d+\.\d+\.\d+)',clause)
                            if m and installed_tuple and _version(m.group(1))[0]==installed_tuple[0]: bounds.append(m.group(1))
                        fix=min(bounds,key=_version) if bounds else None
                    same_branch = True
                    if fix:
                        fixed = _version(fix)
                        installed = _version(asset.get("version"))
                        if repo == "php/php-src":
                            same_branch = bool(fixed and installed and fixed[:2] == installed[:2])
                        elif repo in ("nodejs/node", "electron/electron"):
                            same_branch = bool(fixed and installed and fixed[0] == installed[0])
                    if node_raw and patched_match is True:
                        matched = False
                    assessment = ("unknown" if php_extension else
                                  "affected" if matched is True and same_branch else
                                  "not_affected" if matched is False else "unknown")
                    findings.append({
                        "asset": asset, "advisory_id": advisory.get("ghsa_id") or advisory.get("id") or advisory.get("ref") or advisory.get("_record_id"),
                        "cve_ids": sorted(set(_cves(advisory) + (advisory.get("cve", []) if node_raw and isinstance(advisory.get("cve"), list) else []))),
                        "upstream_fixed": "yes" if fix and same_branch else "unknown",
                        "vendor_release_available": "unknown", "installed": assessment,
                        "running": "unknown", "installed_asset_name": asset.get("name"),
                        "running_asset_name": None, "fixed_versions": [fix] if fix and same_branch else [],
                        "vendor_fixed_versions": [], "assessment": assessment,
                        "installed_version": asset.get("version"), "vulnerable_version_range": vulnerable,
                        "first_patched_version": fix if same_branch else None, "repository": repo,
                        "upstream_reference": advisory.get("ref") if node_raw else None,
                        "component_candidate": package.get("name"),
                        "component_condition": "extension applicability unknown" if php_extension else "repository-bound component",
                        "evidence": [{"source_url": url, "source_sha256": digest,
                                      "retrieved_at": retrieved, "kind": "Node.js core security index" if repo == "nodejs/node" and node_raw else "GitHub repository advisory"}],
                    })
    return findings, errors


if __name__ == "__main__":
    # Minimal self-check keeps the range parser's conservative boundary explicit.
    assert _range_match("20.2.0", ">=20.0.0 <20.3.0 || >=21.1.0, <21.2.0") is True
    assert _range_match("20.3.0", ">=20.0.0 <20.3.0") is False
    assert _range_match("20.2.0", "^20.0.0") is True
