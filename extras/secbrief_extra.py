#!/usr/bin/env python3
"""Bounded, static companion checks for npm, Composer and Electron app.asar."""
from __future__ import annotations
import argparse, contextlib, csv, fcntl, json, os, re, shutil, struct, subprocess, sys, tempfile, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MAX_LOCK = 64 * 1024 * 1024
MAX_ASAR_HEADER = 8 * 1024 * 1024
MAX_ASAR_ENTRIES = 100_000
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 64
MAX_NATIVE_FILES = 5000
MAX_METADATA = 1024 * 1024
FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
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

def _asar_tree(path):
    p = Path(path)
    if p.stat().st_size > MAX_SCAN_BYTES: raise ScanError("ASAR exceeds scan byte limit")
    with p.open("rb") as f:
        first = f.read(8)
        if len(first) != 8: raise ScanError("truncated ASAR preamble")
        size_payload, header_size = struct.unpack("<II", first)
        if size_payload != 4 or not 8 <= header_size <= MAX_ASAR_HEADER or 8 + header_size > p.stat().st_size:
            raise ScanError("invalid or oversized ASAR header")
        raw = f.read(header_size)
        if len(raw) != header_size: raise ScanError("truncated ASAR header")
        payload_size, str_len = struct.unpack("<II", raw[:8])
        if payload_size != header_size - 4 or str_len > header_size - 8: raise ScanError("invalid ASAR header string length")
        tree = json.loads(raw[8:8+str_len].decode("utf-8"))
    entries = []
    def walk(node, prefix="", depth=0):
        if depth > MAX_DEPTH: raise ScanError("ASAR depth limit exceeded")
        if not isinstance(node, dict): raise ScanError("malformed ASAR tree")
        for name, child in (node.get("files") or {}).items():
            if not isinstance(name, str) or name in (".", "..") or "/" in name or "\\" in name: raise ScanError("unsafe ASAR path")
            loc = f"{prefix}/{name}".strip("/")
            if len(entries) >= MAX_ASAR_ENTRIES: raise ScanError("ASAR entry limit exceeded")
            if not isinstance(child, dict): raise ScanError("malformed ASAR entry")
            entries.append((loc, child))
            if "files" in child: walk(child, loc, depth + 1)
    walk(tree)
    return p, header_size, entries

def inspect_asar(path):
    """Read bounded ASAR metadata; ASAR links are never followed or extracted."""
    p, header_size, entries = _asar_tree(path)
    files = dict(entries)
    result = {"path": str(p), "installed_version": None, "electron": None, "node": None, "status": "unknown", "reason": "application package metadata absent", "assets": []}
    for loc, entry in entries:
        is_npm = "/node_modules/" in "/" + loc
        is_app = loc in ("package.json", "app/package.json", "resources/app/package.json")
        if not loc.endswith("package.json") or not (is_npm or is_app): continue
        if entry.get("link") is not None or entry.get("unpacked"): continue
        try:
            size, offset = entry.get("size"), int(entry.get("offset", -1))
            if not isinstance(size, int) or size < 0 or size > MAX_METADATA or offset < 0 or header_size + 8 + offset + size > p.stat().st_size: raise ScanError("invalid ASAR resource bounds")
            with p.open("rb") as f: f.seek(header_size + 8 + offset); data = f.read(size)
            if len(data) != size: raise ScanError("truncated ASAR resource")
            meta = json.loads(data.decode("utf-8"))
            if isinstance(meta, dict) and meta.get("version"):
                if meta.get("name"):
                    result["assets"].append(dict(ecosystem="npm", name=meta["name"], version=meta["version"], source=str(p), location=loc, evidence="ASAR package.json"))
                if is_app and result["installed_version"] is None:
                    result["installed_version"] = meta["version"]; result["status"] = "observed"; result["reason"] = "static package metadata only"
        except (ValueError, UnicodeError, ScanError) as e:
            result.setdefault("errors", []).append(f"{loc}: {e}")
    result["native_libraries"] = []
    result["metadata_candidates"] = []
    scanned = 0
    for loc, entry in entries:
        suffix = Path(loc).suffix.lower()
        if suffix in (".node", ".so", ".dll", ".dylib"):
            result["native_libraries"].append({"path": loc, "version": None, "reason": "packed native binary; version unknown, not executed"})
        if suffix not in (".js", ".cjs", ".mjs") or entry.get("unpacked") or entry.get("link") is not None: continue
        try:
            size, offset = entry.get("size"), int(entry.get("offset", -1))
            if not isinstance(size, int) or size < 0 or offset < 0 or header_size + 8 + offset + size > p.stat().st_size: raise ScanError("invalid JS resource bounds")
            length = min(size, MAX_METADATA, MAX_SCAN_BYTES-scanned)
            if length <= 0: break
            with p.open("rb") as f:
                f.seek(header_size+8+offset); data = f.read(length)
            scanned += len(data)
            for match in re.finditer(rb"sourceMappingURL=([^\s*]+)", data):
                if len(result["metadata_candidates"]) >= 5000: break
                result["metadata_candidates"].append({"path": loc, "candidate": match[1].decode("utf-8", "replace")[:256], "verified_installed_version": False})
        except (ValueError, OSError, ScanError) as e: result.setdefault("errors", []).append(f"{loc}: {e}")
    result["coverage"] = {"archive_entries": len(entries), "js_bytes_scanned": scanned, "js_prefix_limit": MAX_METADATA, "native_versions": "unknown unless separately evidenced"}
    return result

def _safe_walk(root):
    root = Path(root)
    if not root.exists() or root.is_symlink() or not root.is_dir(): return
    real = root.resolve()
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current)/d).is_symlink() and (Path(current)/d).resolve().is_relative_to(real)]
        for name in files:
            f = Path(current)/name
            if f.is_symlink() or not f.resolve().is_relative_to(real): continue
            yield f

def inspect_app_directory(root):
    root=Path(root); assets=[]; errors=[]; native=[]; candidates=[]; consumed=0; count=0
    for f in _safe_walk(root):
        count += 1
        if count > MAX_ASAR_ENTRIES: errors.append("directory entry limit exceeded"); break
        rel=str(f.relative_to(root))
        if f.name == "package.json":
            try:
                size=f.stat().st_size
                if size > MAX_METADATA or consumed + size > MAX_SCAN_BYTES: raise ScanError("package metadata byte limit exceeded")
                consumed += size
                m=json.loads(f.read_text(encoding="utf-8"))
                if isinstance(m,dict) and m.get("name") and m.get("version"):
                    npm=any(x == "node_modules" for x in f.parts)
                    assets.append(dict(ecosystem="npm",name=m["name"],version=m["version"],source=str(root),location=rel,evidence="filesystem package.json",installed_version_verified=True if npm else False))
            except (OSError,ValueError,ScanError) as e: errors.append(f"{rel}: {e}")
        if f.suffix.lower() in (".node", ".so", ".dll", ".dylib"):
            native.append({"path":rel,"type":f.suffix.lower(),"dependencies":[]})
        if f.suffix.lower() in (".js", ".cjs", ".mjs") and consumed < MAX_SCAN_BYTES:
            try:
                with f.open("rb") as stream: data=stream.read(min(MAX_METADATA,MAX_SCAN_BYTES-consumed))
                consumed+=len(data)
                for match in re.findall(rb"sourceMappingURL=([^\s*]+)|(?:license|version)\s*[:=]\s*[\"']?([^\s*\"']+)",data,re.I):
                    v=(match[0] or match[1]).decode("utf-8","replace")[:256]
                    candidates.append({"path":rel,"candidate":v,"verified_installed_version":False})
            except OSError as e: errors.append(f"{rel}: {e}")
    for item in native[:MAX_NATIVE_FILES]:
        tool=next((shutil.which(x) for x in ("readelf","objdump","otool") if shutil.which(x)),None)
        if not tool: break
        args=[tool,"-d" if Path(tool).name == "readelf" else "-p",str(Path(root)/item["path"])] if Path(tool).name in ("readelf","objdump") else [tool,"-L",str(Path(root)/item["path"])]
        try:
            proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False,env={"PATH":os.environ.get("PATH","")})
            item["dependencies"]=[line.strip()[:512] for line in proc.stdout.decode("utf-8","replace").splitlines()[:100] if "NEEDED" in line or ".dylib" in line or ".dll" in line]
        except (OSError,subprocess.TimeoutExpired): item["dependency_parse"]="unavailable/timeout"
    return {"path":str(root),"assets":assets,"native_libraries":native[:MAX_NATIVE_FILES],"metadata_candidates":candidates[:5000],"coverage":{"files_seen":count,"bytes_scanned":consumed,"native_libraries_capped":len(native)>MAX_NATIVE_FILES},"errors":errors}

def inspect_runtime(binary):
    p=Path(binary)
    if p.stat().st_size > MAX_SCAN_BYTES: return {"status":"unknown","reason":"binary exceeds fuse scan limit"}
    data=p.read_bytes()
    pos=data.find(FUSE_SENTINEL)
    fuse="unknown"
    if pos >= 0 and data.find(FUSE_SENTINEL,pos+1) < 0 and pos+len(FUSE_SENTINEL)+2 < len(data):
        version,n=data[pos+len(FUSE_SENTINEL):pos+len(FUSE_SENTINEL)+2]
        wire=data[pos+len(FUSE_SENTINEL)+2:pos+len(FUSE_SENTINEL)+2+n]
        if version == 1 and n > 0 and len(wire)==n and wire[0] in (ord('0'),ord('1'),ord('r')):
            fuse={ord('0'):"disabled",ord('1'):"enabled",ord('r'):"removed"}[wire[0]]
    result={"status":"unknown","run_as_node_fuse":fuse,"source":"Electron fuse wire in binary"}
    if fuse != "enabled": result["reason"]="runtime not invoked: runAsNode fuse is not confirmed enabled"; return result
    env={k:v for k,v in os.environ.items() if k not in ("NODE_OPTIONS","NODE_PATH","ELECTRON_RUN_AS_NODE","LD_PRELOAD","DYLD_INSERT_LIBRARIES")}
    env["ELECTRON_RUN_AS_NODE"]="1"
    try:
        proc=subprocess.run([str(p),"-p","JSON.stringify(process.versions)"],capture_output=True,text=True,timeout=10,env=env,check=False)
        if proc.returncode or len(proc.stdout)>65536: raise ScanError("runtime probe failed or oversized output")
        versions=json.loads(proc.stdout.strip())
        result.update(status="observed",versions={k:{"value":v,"source":"explicit Electron RUN_AS_NODE probe"} for k,v in versions.items() if isinstance(v,str)},reason="explicit opt-in runtime probe")
    except (OSError,subprocess.TimeoutExpired,ValueError,ScanError) as e: result["reason"]=str(e)
    return result

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
        electron = []; runtime = None; directory_scans = []
        for raw in args.asar:
            try:
                info=inspect_asar(raw); electron.append(info); assets.extend(info.get("assets", [])); errors.extend(info.get("errors", []))
                for root in (Path(str(raw)+".unpacked"), Path(raw).parent/"app"):
                    if root.exists():
                        scan=inspect_app_directory(root); directory_scans.append(scan); assets.extend(scan["assets"]); errors.extend(scan["errors"])
            except Exception as e: errors.append(f"ASAR {raw}: {e}"); electron.append({"path": raw, "installed_version": None, "electron": None, "node": None, "status": "unknown", "reason": str(e),"assets":[]})
        if getattr(args,"probe_runtime",False):
            if not getattr(args,"electron_binary",None): errors.append("runtime probe requires --electron-binary PATH")
            else:
                try: runtime=inspect_runtime(args.electron_binary)
                except (OSError,ScanError) as e: runtime={"status":"unknown","reason":str(e)}
        findings = []
        if args.online:
            findings, osv_errors = osv_scan(assets); errors.extend(osv_errors)
            kev_ok, kev_error = kev_lookup(findings)
            if not kev_ok: errors.append("KEV unavailable: " + str(kev_error))
        else:
            kev_ok = False
        now = datetime.now(timezone.utc).isoformat()
        report = {"schema": "secbrief-extra/report-v1", "generated_at": now, "online": args.online, "assets": assets, "findings": findings, "electron_static": electron, "electron_directories":directory_scans, "electron_runtime":runtime, "errors": errors, "status": "degraded" if errors or (args.online and not kev_ok) else ("complete" if args.online else "inventory_only")}
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
    r = sub.add_parser("run"); r.add_argument("--lockfile", action="append", default=[]); r.add_argument("--asar", action="append", default=[]); r.add_argument("--output", default="secbrief-extra-out"); r.add_argument("--online", action="store_true", help="send package names and versions to OSV/CISA"); r.add_argument("--electron-binary"); r.add_argument("--probe-runtime", action="store_true", help="explicit runtime probe only if runAsNode fuse is enabled")
    d = sub.add_parser("doctor"); d.add_argument("--output", default="secbrief-extra-out")
    h = sub.add_parser("handoff"); h.add_argument("--report", default="secbrief-extra-out/report.json"); h.add_argument("--output", default="secbrief-extra-out/handoff.json")
    a = p.parse_args(argv)
    if a.cmd == "inventory":
        assets, errors = inventory(a.lockfile); electron=[]
        for path in a.asar:
            try:
                info=inspect_asar(path); electron.append(info); assets.extend(info.get("assets", [])); errors.extend(info.get("errors", []))
                for root in (Path(str(path)+".unpacked"), Path(path).parent/"app"):
                    if root.exists():
                        scan=inspect_app_directory(root); electron.append(scan); assets.extend(scan["assets"]); errors.extend(scan["errors"])
            except Exception as e: errors.append(f"ASAR {path}: {e}")
        atomic_json(Path(a.output)/"inventory.json", {"assets": assets, "electron_static": electron, "errors": errors})
        print(json.dumps({"assets": len(assets), "electron_static": len(electron), "errors": errors})); return 2 if errors else 0
    if a.cmd == "run": return run(a)
    if a.cmd == "doctor":
        for name in ("report.json", "state.json", "alerts.json"): print(f"{name}: {'present' if (Path(a.output)/name).exists() else 'missing'}")
        return 0
    handoff(a.report, a.output); return 0
if __name__ == "__main__": sys.exit(main())
