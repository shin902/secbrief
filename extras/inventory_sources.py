#!/usr/bin/env python3
"""Explicit host inventory and primary-source advisory snapshots; read-only only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

MAX_OUTPUT = 16 * 1024 * 1024
MAX_FEED = 8 * 1024 * 1024
OSV_ENDPOINT = "https://api.osv.dev/v1/query"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _run(path, args, timeout=15):
    """Run only a configured absolute executable with fixed, read-only arguments."""
    executable = Path(path).expanduser()
    if not executable.is_absolute():
        raise ValueError("executable path must be absolute")
    result = subprocess.run([str(executable), *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError("collector output limit exceeded")
    if result.returncode:
        raise ValueError(f"exit {result.returncode}: {result.stderr.decode('utf-8', 'replace')[:300]}")
    return result.stdout.decode("utf-8", "replace")


def _asset(ecosystem, name, version, source, **extra):
    return {"ecosystem": ecosystem, "name": name, "version": version,
            "source": str(source), "location": extra.pop("location", str(source)), **extra}


def _add_error(errors, source, exc):
    errors.append({"source": str(source), "error": str(exc)[:500]})


def _collect_os(config, assets, errors, coverage):
    formats = {
        "dpkg": ("dpkg", ["-W", "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n"]),
        "pacman": ("pacman", ["-Q"]),
        "rpm": ("rpm", ["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"]),
    }
    for kind, path in config.get("os_package_managers", {}).items():
        if kind not in formats:
            _add_error(errors, kind, "unsupported OS package manager")
            continue
        label, args = formats[kind]
        if kind == "dpkg" and Path(path).name == "dpkg":
            _add_error(errors, path, "configure dpkg-query, not the package-mutating dpkg frontend")
            coverage["os"][kind] = {"status": "unknown"}
            continue
        try:
            count = 0
            for line in _run(path, args).splitlines():
                cols = line.split("\t") if kind != "pacman" else line.rsplit(" ", 1)
                if len(cols) < 2 or not cols[0].strip() or not cols[1].strip():
                    continue
                name, version = cols[0].strip(), cols[1].strip()
                extra = {"architecture": cols[2].strip()} if kind in ("dpkg", "rpm") and len(cols) > 2 else {}
                assets.append(_asset(label, name, version, path, **extra))
                count += 1
            coverage["os"][kind] = {"status": "observed", "packages": count}
        except Exception as exc:
            coverage["os"][kind] = {"status": "unknown"}
            _add_error(errors, path, exc)


def _collect_pip(env_paths, assets, errors, coverage):
    coverage["python_envs"] = []
    for raw in env_paths:
        env_path = Path(raw).expanduser()
        py = env_path / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        record: dict[str, object] = {"path": str(env_path), "python": str(py), "status": "unknown"}
        try:
            data = json.loads(_run(py, ["-m", "pip", "list", "--format=json"]))
            if not isinstance(data, list):
                raise ValueError("pip list response is not a list")
            for item in data:
                if isinstance(item, dict) and item.get("name") and item.get("version"):
                    assets.append(_asset("PyPI", item["name"], item["version"], str(env_path),
                                         environment=str(env_path), python=str(py)))
            record["status"] = "observed"
            record["packages"] = len(data)
        except Exception as exc:
            _add_error(errors, env_path, exc)
        coverage["python_envs"].append(record)


def _collect_runtimes(paths, probe, runtimes, errors):
    for kind, raw_paths in paths.items():
        if kind not in ("node", "php", "bun"):
            _add_error(errors, kind, "supported runtimes are node, php, bun")
            continue
        for raw in raw_paths if isinstance(raw_paths, list) else [raw_paths]:
            row = {"runtime": kind, "executable": str(raw), "version": None,
                   "status": "not_probed", "probe_consent": bool(probe)}
            if probe:
                args = {"node": ["--version"], "bun": ["--version"], "php": ["--version"]}[kind]
                try:
                    output = _run(raw, args, timeout=10).strip().splitlines()
                    if not output:
                        raise ValueError("empty version output")
                    version = output[0][:300].strip()
                    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version.lstrip("v"))
                    row.update(version=match.group(0) if match else None,
                               reported_version=version, status="observed")
                except Exception as exc:
                    row.update(status="unknown")
                    _add_error(errors, raw, exc)
            runtimes.append(row)


def _runtime_assets(runtimes):
    return [_asset(f"{row['runtime']}-runtime", row["runtime"], row["version"], row["executable"],
                   runtime_path=row["executable"])
            for row in runtimes if row.get("version")]


def _collect_containers(config, probe, errors):
    result = {"images": [], "running": [], "probes": [], "status": "not_configured"}
    docker = config.get("docker_path")
    if not docker:
        return result
    try:
        raw = _run(docker, ["ps", "--no-trunc", "--format", "{{json .}}"])
        for line in raw.splitlines():
            if line.strip():
                item = json.loads(line)
                result["running"].append({"id": item.get("ID"), "image": item.get("Image"),
                                          "names": item.get("Names"), "status": item.get("Status")})
        raw = _run(docker, ["image", "ls", "--no-trunc", "--format", "{{json .}}"])
        for line in raw.splitlines():
            if line.strip():
                item = json.loads(line)
                result["images"].append({"id": item.get("ID"), "repository": item.get("Repository"),
                                         "tag": item.get("Tag"), "digest": item.get("Digest")})
        result["status"] = "observed"
    except Exception as exc:
        result["status"] = "unknown"
        _add_error(errors, docker, exc)
        return result
    if probe:
        for item in result["running"]:
            cid = item.get("id")
            if not cid:
                continue
            for check in config.get("container_probes", []):
                if check not in ("node", "php", "bun"):
                    _add_error(errors, "container_probes", f"unsupported probe: {check}")
                    continue
                command = {"node": ["node", "--version"], "php": ["php", "--version"],
                          "bun": ["bun", "--version"]}[check]
                row = {"container_id": cid, "probe": check, "status": "unknown", "output": None}
                try:
                    out = _run(docker, ["exec", cid, *command], timeout=10).strip().splitlines()
                    reported = out[0][:300] if out else ""
                    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", reported.lstrip("v"))
                    row.update(status="observed", output=reported,
                               version=match.group(0) if match else None)
                except Exception as exc:
                    _add_error(errors, f"docker exec {cid} {check}", exc)
                result["probes"].append(row)
    return result


def _fetch_json(url, timeout=30):
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ValueError("source URL must use https")
    request = urllib.request.Request(url, headers={"User-Agent": "secbrief-inventory-sources/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_FEED + 1)
        final_url = response.geturl()
    if len(data) > MAX_FEED:
        raise ValueError("feed exceeds size limit")
    parsed = json.loads(data)
    return {"source_url": url, "retrieved_at": utc_now(),
            "sha256": hashlib.sha256(data).hexdigest(), "final_url": final_url,
            "document": parsed}


def _fetch_source(url, source_format="json"):
    if source_format == "json":
        return _fetch_json(url)
    if source_format not in ("rss", "atom"):
        raise ValueError("source format must be json, rss, or atom")
    request = urllib.request.Request(url, headers={"User-Agent": "secbrief-inventory-sources/1.0", "Accept": "application/rss+xml, application/xml, text/xml"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(MAX_FEED + 1)
    if len(raw) > MAX_FEED:
        raise ValueError("feed exceeds size limit")
    root = ET.fromstring(raw)
    items = []
    nodes = root.findall(".//item") if source_format == "rss" else root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for item in nodes:
        def text(name):
            node = item.find(name) if source_format == "rss" else item.find(f"{{http://www.w3.org/2005/Atom}}{name}")
            return "" if node is None or node.text is None else node.text.strip()
        links = item.findall("link") if source_format == "rss" else item.findall("{http://www.w3.org/2005/Atom}link")
        link = text("link") if source_format == "rss" else next((n.get("href", "") for n in links if n.get("rel", "alternate") == "alternate"), "")
        items.append({"id": text("guid") or text("id") or link, "title": text("title"),
                      "description": text("description") or text("summary") or text("content"), "link": link})
    return {"source_url": url, "retrieved_at": utc_now(),
            "sha256": hashlib.sha256(raw).hexdigest(), "final_url": url,
            "format": source_format, "document": {"items": items}}


def _fixed_events(vuln, ecosystem, name):
    fixes = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name") != name or pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if isinstance(event.get("fixed"), str):
                    fixes.append(event["fixed"])
    return sorted(set(fixes))


def _osv_asset(asset):
    names = {"npm": ("npm", "npm"), "pypi": ("PyPI", "PyPI"),
             "packagist": ("Packagist", "Packagist")}
    for key, value in names.items():
        if asset.get("ecosystem", "").lower() == key:
            return {"package": {"name": asset["name"], "ecosystem": value[1]}, "version": asset["version"]}
    return None


def _advisory(asset, advisory_id, cves=None, fixes=None, upstream="unknown", vendor="unknown", evidence=None):
    return {"asset": asset, "advisory_id": advisory_id, "cve_ids": cves or [],
            "upstream_fixed": upstream, "vendor_release_available": vendor,
            "installed": "unknown", "running": "unknown",
            "installed_asset_name": asset.get("name"), "running_asset_name": None,
            "fixed_versions": fixes or [], "vendor_fixed_versions": [], "evidence": evidence or []}


def _check_osv(assets, errors):
    findings = []
    for asset in assets:
        query = _osv_asset(asset)
        if query is None:
            continue
        try:
            body = json.dumps(query).encode()
            req = urllib.request.Request(OSV_ENDPOINT, data=body, headers={"Content-Type": "application/json", "User-Agent": "secbrief-inventory-sources/1.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read(MAX_FEED + 1)
            if len(data) > MAX_FEED:
                raise ValueError("OSV response exceeds limit")
            response = json.loads(data)
            if not isinstance(response, dict) or not isinstance(response.get("vulns", []), list):
                raise ValueError("OSV response schema is invalid")
            rows = response.get("vulns", [])
            if any(not isinstance(v, dict) for v in rows):
                raise ValueError("OSV vulnerability row schema is invalid")
            if response.get("next_page_token"):
                raise ValueError("OSV pagination is incomplete; refusing a clean result")
            for vuln in rows:
                vid = vuln.get("id")
                if not vid:
                    continue
                fixes = _fixed_events(vuln, query["package"]["ecosystem"], asset["name"])
                aliases = [vuln.get("id", ""), *vuln.get("aliases", [])]
                cves = sorted({v for v in aliases if isinstance(v, str) and v.startswith("CVE-")})
                findings.append(_advisory(asset, vid, cves, fixes, "yes" if fixes else "unknown",
                                          evidence=[{"source_url": f"https://osv.dev/vulnerability/{vid}", "kind": "OSV exact-version query match", "fixed_versions": fixes}]))
                findings[-1]["installed"] = "yes"
        except Exception as exc:
            _add_error(errors, f"OSV {asset.get('ecosystem')}:{asset.get('name')}@{asset.get('version')}", exc)
            findings.append(_advisory(asset, None, evidence=[{"kind": "OSV query failed", "status": "unknown"}]))
    return findings


def _records(document):
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("vulns", "advisories", "items", "data"):
            if isinstance(document.get(key), list):
                return document[key]
        if isinstance(document.get("id"), str) or isinstance(document.get("ghsa_id"), str):
            return [document]
    return []


def _reviewed_findings(assets, snapshots, rules, errors):
    findings = []
    for rule in rules:
        url = rule.get("source_url")
        snapshot = next((s for s in snapshots if s.get("source_url") == url), None)
        if not snapshot or snapshot["sha256"] != rule.get("source_sha256"):
            _add_error(errors, url or "reviewed_rule", "reviewed source hash mismatch; rule not applied")
            continue
        record = next((r for r in _records(snapshot["document"])
                       if (r.get("id") or r.get("ghsa_id")) == rule.get("advisory_id")), None)
        if not record:
            _add_error(errors, url, f"reviewed advisory {rule.get('advisory_id')} absent from source")
            continue
        for asset in assets:
            if asset.get("ecosystem", "").lower() != str(rule.get("ecosystem", "")).lower() or asset.get("name") != rule.get("package"):
                continue
            if asset.get("runtime_path") and rule.get("runtime_path") != asset["runtime_path"]:
                continue
            # Operator reviewed mappings require exact version membership, never guessed ranges.
            affected_versions = rule.get("affected_versions", [])
            if asset.get("version") not in affected_versions:
                continue
            evidence_text = rule.get("evidence_text", "")
            source_text = json.dumps(record, sort_keys=True, ensure_ascii=False)
            if not evidence_text or evidence_text not in source_text:
                _add_error(errors, url, "reviewed evidence text is not present verbatim")
                continue
            fixes = rule.get("vendor_fixed_versions", [])
            proof_text = json.dumps(record, sort_keys=True, ensure_ascii=False)
            fixes = [v for v in fixes if isinstance(v, str) and v and v in proof_text]
            upstream_fixes = [v for v in rule.get("upstream_fixed_versions", [])
                              if isinstance(v, str) and v and v in proof_text]
            findings.append(_advisory(asset, rule["advisory_id"], rule.get("cve_ids", []),
                                      upstream_fixes, "yes" if upstream_fixes else "unknown",
                                      "yes" if fixes else "unknown",
                                      [{"source_url": url, "source_sha256": snapshot["sha256"],
                                                "kind": "operator-reviewed exact-version mapping", "text": evidence_text,
                                                "vendor_fixed_versions": fixes,
                                                "retrieved_at": snapshot["retrieved_at"]}]))
            findings[-1]["vendor_fixed_versions"] = fixes
            findings[-1]["installed"] = "yes"
    return findings


def _release_drift(assets, snapshots, source_url=None):
    updates = []
    for snap in snapshots:
        if not source_url or snap.get("source_url") != source_url:
            continue
        doc = snap.get("document")
        candidates = doc if isinstance(doc, list) else [doc] if isinstance(doc, dict) else []
        stable = []
        for item in candidates:
            if not isinstance(item, dict) or item.get("prerelease") or item.get("draft"):
                continue
            version = item.get("version") or item.get("tag_name") or item.get("name")
            match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version) if isinstance(version, str) else None
            if match:
                stable.append((tuple(map(int, match.groups())), ".".join(match.groups())))
        latest = max(stable)[1] if stable else None
        if isinstance(doc, dict) and not stable:
            fallback = doc.get("latest") or doc.get("version") or doc.get("tag_name")
            if isinstance(fallback, str):
                match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", fallback)
                if match:
                    latest = ".".join(match.groups())
        for asset in assets:
            if asset.get("ecosystem", "").lower() == "electron" and asset.get("version") and latest:
                updates.append({"asset": asset, "latest_release": latest,
                                "drift": asset["version"] != str(latest),
                                "security_fixed": "unknown",
                                "evidence": {k: snap[k] for k in ("source_url", "retrieved_at", "sha256")}})
    return updates


def collect(config, probe_runtimes=False, online=False):
    """Collect only configured sources; online requests and executable probes are opt-in."""
    config = config or {}
    assets, errors, runtimes = [], [], []
    coverage = {"os": {}, "network_enabled": bool(online), "runtime_probes_enabled": bool(probe_runtimes)}
    _collect_os(config, assets, errors, coverage)
    _collect_pip(config.get("python_env_paths", []), assets, errors, coverage)
    _collect_runtimes(config.get("runtime_paths", {}), probe_runtimes, runtimes, errors)
    assets.extend(_runtime_assets(runtimes))
    containers = _collect_containers(config, probe_runtimes, errors)
    for row in containers["probes"]:
        if row.get("version"):
            assets.append(_asset(f"{row['probe']}-runtime", row["probe"], row["version"],
                                 f"container:{row['container_id']}", runtime_path=f"container:{row['container_id']}"))
    for item in config.get("installed_assets", []):
        if (isinstance(item, dict) and item.get("ecosystem") == "electron"
                and item.get("name") == "electron" and isinstance(item.get("version"), str)
                and re.fullmatch(r"\d+\.\d+\.\d+", item["version"])):
            assets.append(_asset("electron", "electron", item["version"],
                                 item.get("source", "configured installed_assets"),
                                 location=item.get("location", "configured installed_assets")))
    snapshots, findings, updates = [], [], []
    if online:
        sources = list(config.get("primary_json_urls", []))
        sources.extend(config.get("primary_sources", []))
        for source in sources:
            url = source if isinstance(source, str) else source.get("url")
            try:
                snapshots.append(_fetch_source(url, "json" if isinstance(source, str) else source.get("format", "json")))
            except Exception as exc:
                _add_error(errors, url, exc)
        findings.extend(_check_osv(assets, errors))
        findings.extend(_reviewed_findings(assets, snapshots, config.get("reviewed_rules", []), errors))
        updates = _release_drift(assets, snapshots, config.get("electron_release_url"))
    coverage.update({"asset_count": len(assets), "unmatched_surfaces": [
                         "OS vendor package advisories: no configured vendor advisory rules",
                         "runtime package manifests and per-project dependencies: not inventoried",
                         "Electron: only configured installed_assets are inventoried"],
                     "source_provenance": [{"url": s.get("url") if isinstance(s, dict) else s,
                                            "trust": "configured source; not independently verified"}
                                           for s in config.get("primary_sources", [])],
                     "source_snapshots": len(snapshots),
                     "advisory_findings": len(findings), "release_drift_records": len(updates),
                     "status": "degraded" if errors else "complete"})
    return {"assets": assets, "errors": errors, "coverage": coverage,
            "runtimes": runtimes, "containers": containers,
            "source_snapshots": snapshots, "advisories": findings, "release_drift": updates}


def augment_assets(report, assets, config):
    """Join already collected bundle/runtime evidence without extra network calls."""
    known = {(x.get('ecosystem'),x.get('name'),x.get('version'),x.get('source'),x.get('location')) for x in report['assets']}
    added=[]
    for asset in assets:
        key=(asset.get('ecosystem'),asset.get('name'),asset.get('version'),asset.get('source'),asset.get('location'))
        if key not in known:
            report['assets'].append(asset); added.append(asset); known.add(key)
    if report.get('coverage',{}).get('network_enabled'):
        report['advisories'].extend(_reviewed_findings(added,report['source_snapshots'],config.get('reviewed_rules',[]),report['errors']))
        report['release_drift']=_release_drift(report['assets'],report['source_snapshots'],config.get('electron_release_url'))
    report.setdefault('coverage', {})['asset_count']=len(report['assets'])
    report['coverage']['status']='degraded' if report['errors'] else 'complete'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collect", nargs="?", choices=["collect"], default="collect")
    parser.add_argument("--config", required=True)
    parser.add_argument("--probe-runtimes", action="store_true", help="consent to execute configured version probes")
    parser.add_argument("--online", action="store_true", help="fetch configured HTTPS sources and query OSV")
    parser.add_argument("--output", help="write JSON result here; stdout when omitted")
    args = parser.parse_args(argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        result = collect(config, probe_runtimes=args.probe_runtimes, online=args.online)
        text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 2 if result["errors"] else 0
    except Exception as exc:
        print(f"inventory_sources: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
