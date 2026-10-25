#!/usr/bin/env python3
"""Bounded, static companion checks for npm, Composer and Electron app.asar."""
from __future__ import annotations
import argparse, contextlib, csv, fcntl, json, os, struct, sys, tempfile, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MAX_LOCK = 64 * 1024 * 1024
MAX_ASAR_HEADER = 8 * 1024 * 1024
OSV = "https://api.osv.dev/v1"

class ScanError(Exception): pass

def read_json(path: Path, limit=MAX_LOCK):
    if path.stat().st_size > limit: raise ScanError(f"oversized input: {path}")
    with path.open("r", encoding="utf-8") as f: return json.load(f)

def inventory(paths):
    """Read explicit lockfiles. Each identity includes source path and ecosystem."""
    assets, errors = [], []
    for raw in paths:
        path = Path(raw).expanduser()
        try:
            if path.name == "package-lock.json":
                doc = read_json(path)
                if doc.get("lockfileVersion") not in (2, 3): raise ScanError("npm lockfileVersion must be 2 or 3")
                for loc, item in doc.get("packages", {}).items():
                    name = item.get("name") or (loc.rsplit("node_modules/", 1)[-1] if "node_modules/" in loc else "")
                    if loc and name and item.get("version"):
                        assets.append(dict(ecosystem="npm", name=name, version=item["version"], source=str(path), location=loc or "."))
            elif path.name == "composer.lock":
                doc = read_json(path)
                for item in doc.get("packages", []) + doc.get("packages-dev", []):
                    if item.get("name") and item.get("version"):
                        assets.append(dict(ecosystem="Packagist", name=item["name"], version=item["version"], source=str(path), location=item["name"]))
            else: raise ScanError("only package-lock.json and composer.lock are supported")
        except (OSError, ValueError, ScanError) as e: errors.append(f"{path}: {e}")
    return assets, errors

def inspect_asar(path):
    """Parse only the bounded ASAR header and package.json metadata; never extract."""
    p = Path(path)
    with p.open("rb") as f:
        first = f.read(8)
        if len(first) != 8: raise ScanError("truncated ASAR preamble")
        size_payload, header_size = struct.unpack("<II", first)
        if size_payload != 4 or not 8 <= header_size <= MAX_ASAR_HEADER:
            raise ScanError("invalid or oversized ASAR header")
        raw = f.read(header_size)
        if len(raw) != header_size: raise ScanError("truncated ASAR header")
        payload_size, str_len = struct.unpack("<II", raw[:8])
        if payload_size != header_size - 4 or str_len > header_size - 8:
            raise ScanError("invalid ASAR header string length")
        tree = json.loads(raw[8:8+str_len].decode("utf-8"))
    def lookup(node, parts):
        for part in parts:
            node = (node.get("files") or {}).get(part)
            if not isinstance(node, dict): return None
        return node
    entry = lookup(tree, ["package.json"])
    if entry is None:
        # Common application bundle location; only inspect exact metadata paths.
        for parts in (["app", "package.json"], ["resources", "app", "package.json"]):
            entry = lookup(tree, parts)
            if entry is not None: break
    if entry is None: return {"path": str(p), "installed_version": None, "electron": None, "node": None, "status": "unknown", "reason": "package.json absent from ASAR header"}
    if entry.get("unpacked") or "offset" not in entry or not isinstance(entry.get("size"), int):
        return {"path": str(p), "installed_version": None, "electron": None, "node": None, "status": "unknown", "reason": "package.json is external/unpacked; no extraction performed"}
    offset = int(entry["offset"])
    size = entry["size"]
    if offset < 0 or size < 0 or size > 1024*1024: raise ScanError("invalid or oversized package.json resource")
    # ASAR file-data starts at header_size + 8; offsets are decimal strings.
    try: offset = int(entry["offset"])
    except (ValueError, TypeError): raise ScanError("invalid ASAR resource offset")
    with p.open("rb") as f:
        f.seek(header_size + 8 + offset)
        data = f.read(size)
    if len(data) != size: raise ScanError("truncated package.json resource")
    meta = json.loads(data.decode("utf-8"))
    return {"path": str(p), "installed_version": meta.get("version"), "electron": None, "node": None,
            "status": "observed" if meta.get("version") else "unknown", "reason": "static application package metadata only"}

def http_json(url, body=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"User-Agent": f"secbrief-extra/{VERSION}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response: return json.loads(response.read())

def fixed_versions(vuln, asset):
    out = set()
    for affected in vuln.get("affected", []):
        package = affected.get("package") or {}
        if package.get("name") != asset["name"] or package.get("ecosystem") != asset["ecosystem"]: continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if event.get("fixed"): out.add(event["fixed"])
    return sorted(out)

def osv_scan(assets, http=http_json):
    findings, errors = [], []
    for start in range(0, len(assets), 1000):
        batch = assets[start:start+1000]
        try:
            result = http(OSV + "/querybatch", {"queries": [{"package": {"name": a["name"], "ecosystem": a["ecosystem"]}, "version": a["version"]} for a in batch]})
            rows = result.get("results", [])
            if len(rows) != len(batch): raise ScanError("OSV result count mismatch")
            if any(row.get("next_page_token") for row in rows): raise ScanError("OSV pagination requires follow-up; coverage incomplete")
            for asset, row in zip(batch, rows):
                for stub in row.get("vulns", []):
                    vid = stub.get("id")
                    if not vid: continue
                    try: detail = http(OSV + "/vulns/" + vid)
                    except Exception as e:
                        errors.append(f"OSV detail {vid}: {e}")
                        findings.append({"asset": asset, "advisory_id": vid, "status": "unknown", "kev": None, "fixed_versions": [], "url": f"https://osv.dev/vulnerability/{vid}"})
                        continue
                    cves = sorted({x for x in [detail.get("id", ""), *detail.get("aliases", [])] if isinstance(x, str) and x.startswith("CVE-")})
                    findings.append({"asset": asset, "advisory_id": vid, "cve_ids": cves, "status": "affected (OSV exact-version match)", "kev": None, "fixed_versions": fixed_versions(detail, asset), "summary": detail.get("summary", ""), "url": f"https://osv.dev/vulnerability/{vid}"})
        except Exception as e:
            errors.append(f"OSV querybatch: {e}")
            findings.extend({"asset": a, "advisory_id": None, "status": "unknown", "kev": None, "reason": str(e)} for a in batch)
    return findings, errors

def kev_lookup(findings, http=http_json):
    try:
        req = urllib.request.Request("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", headers={"User-Agent": f"secbrief-extra/{VERSION}"})
        with urllib.request.urlopen(req, timeout=30) as r: text = r.read(16*1024*1024).decode("utf-8-sig")
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames or "cveID" not in reader.fieldnames: raise ScanError("invalid KEV CSV schema")
        ids = {row.get("cveID", "").strip() for row in reader}
        if not ids: raise ScanError("empty KEV catalog")
        for f in findings:
            cves = f.get("cve_ids", [])
            f["kev"] = any(cve in ids for cve in cves) if cves else (f.get("advisory_id") in ids if f.get("advisory_id", "").startswith("CVE-") else None)
        return True, None
    except Exception as e:
        for f in findings: f["kev"] = None
        return False, str(e)

def atomic_json(path, obj):
    p = Path(path).expanduser(); p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(obj, f, indent=2, ensure_ascii=False); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(tmp)

def run(args):
    outdir = Path(args.output).expanduser(); outdir.mkdir(parents=True, exist_ok=True)
    lock = outdir / ".run.lock"
    with lock.open("w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        assets, errors = inventory(args.lockfile)
        electron = []
        for raw in args.asar:
            try: electron.append(inspect_asar(raw))
            except Exception as e: errors.append(f"ASAR {raw}: {e}"); electron.append({"path": raw, "installed_version": None, "electron": None, "node": None, "status": "unknown", "reason": str(e)})
        findings = []
        if args.online:
            findings, osv_errors = osv_scan(assets); errors.extend(osv_errors)
            kev_ok, kev_error = kev_lookup(findings)
            if not kev_ok: errors.append("KEV unavailable: " + str(kev_error))
        else:
            kev_ok = False
        now = datetime.now(timezone.utc).isoformat()
        report = {"schema": "secbrief-extra/report-v1", "generated_at": now, "online": args.online, "assets": assets, "findings": findings, "electron_static": electron, "errors": errors, "status": "degraded" if errors or (args.online and not kev_ok) else ("complete" if args.online else "inventory_only")}
        atomic_json(outdir / "report.json", report)
        state_path = outdir / "state.json"
        try: prev = json.loads(state_path.read_text()) if state_path.exists() else {"baseline": False, "findings": {}}
        except (OSError, ValueError) as e:
            errors.append(f"state unavailable: {e}"); report["errors"] = errors; report["status"] = "degraded"
            prev = {"baseline": False, "findings": {}}
        current = {f["asset"]["source"]+"|"+f["asset"]["location"]+"|"+str(f.get("advisory_id")): f for f in findings}
        changed = sorted(k for k, value in current.items() if k not in prev.get("findings", {}) or (value.get("asset"), value.get("status"), value.get("kev"), value.get("fixed_versions")) != (prev["findings"][k].get("asset"), prev["findings"][k].get("status"), prev["findings"][k].get("kev"), prev["findings"][k].get("fixed_versions")))
        changed = sorted(set(changed) | (set(prev.get("findings", {})) - set(current)))
        if report["status"] == "complete":
            report["change_count"] = 0 if not prev["baseline"] else len(changed)
            atomic_json(outdir / "state.json", {"baseline": True, "findings": current, "generated_at": now})
            code = 10 if report["change_count"] else 0
        elif report["status"] == "inventory_only": report["change_count"] = None; changed = []; code = 0
        else: report["change_count"] = None; changed = []; code = 2
        atomic_json(outdir / "report.json", report)
        md = ["# secbrief-extra", "", f"Status: **{report['status']}** | assets: {len(assets)} | findings: {len(findings)}", ""]
        for f in findings:
            md.append(f"- **{f['status']}** {f['asset']['name']}@{f['asset']['version']} — {f.get('advisory_id') or 'advisory unknown'}; KEV={f.get('kev')} fixed hints={', '.join(f.get('fixed_versions', [])) or 'unknown'} ({f['asset']['source']})")
        for e in errors: md.append(f"- **ERROR:** {e}")
        atomic_json(outdir / "alerts.json", {"changed": changed if report['status']=='complete' else [], "status": report['status'], "approval_required": True})
        (outdir / "report.md").write_text("\n".join(md)+"\n", encoding="utf-8")
        return code

def handoff(report_path, output):
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    tasks = []
    for f in report.get("findings", []):
        tasks.append({"asset": f["asset"], "advisory_id": f.get("advisory_id"), "status": f["status"], "evidence_url": f.get("url"), "fixed_version_hints": f.get("fixed_versions", []), "kev": f.get("kev"), "approval_required": True, "instructions": "Review advisory and identify a remediation plan. Do not execute commands or change files without explicit human approval."})
    atomic_json(output, {"schema": "secbrief-extra/handoff-v1", "approval_required": True, "source_report": str(report_path), "tasks": tasks})

def main(argv=None):
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory"); inv.add_argument("--lockfile", action="append", default=[]); inv.add_argument("--asar", action="append", default=[]); inv.add_argument("--output", default="secbrief-extra-out")
    r = sub.add_parser("run"); r.add_argument("--lockfile", action="append", default=[]); r.add_argument("--asar", action="append", default=[]); r.add_argument("--output", default="secbrief-extra-out"); r.add_argument("--online", action="store_true", help="send package names and versions to OSV/CISA")
    d = sub.add_parser("doctor"); d.add_argument("--output", default="secbrief-extra-out")
    h = sub.add_parser("handoff"); h.add_argument("--report", default="secbrief-extra-out/report.json"); h.add_argument("--output", default="secbrief-extra-out/handoff.json")
    a = p.parse_args(argv)
    if a.cmd == "inventory":
        assets, errors = inventory(a.lockfile); electron=[]
        for path in a.asar:
            try: electron.append(inspect_asar(path))
            except Exception as e: errors.append(f"ASAR {path}: {e}")
        atomic_json(Path(a.output)/"inventory.json", {"assets": assets, "electron_static": electron, "errors": errors})
        print(json.dumps({"assets": len(assets), "electron_static": len(electron), "errors": errors})); return 2 if errors else 0
    if a.cmd == "run": return run(a)
    if a.cmd == "doctor":
        for name in ("report.json", "state.json", "alerts.json"): print(f"{name}: {'present' if (Path(a.output)/name).exists() else 'missing'}")
        return 0
    handoff(a.report, a.output); return 0
if __name__ == "__main__": sys.exit(main())
