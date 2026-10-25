#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secbrief — a daily vulnerability briefing for AI-agent-managed machines.

Deterministic core: official free feeds (OSV.dev, CISA KEV, formulae.brew.sh)
matched against the machine's real inventory. No LLM in the automated path:
the briefing is shaped so any LLM can *explain* it, but every fact line is
machine-verified (output gate: a line without an advisory id, installed
version, fix status and KEV flag cannot be emitted).

Sources (free, official, no API keys):
  - OSV.dev querybatch + vuln details (aggregates NVD/GHSA/vendor advisories;
    Ubuntu/Debian entries carry the DISTRO fixed versions, which is the truth
    for distro packages — upstream version ranges would misjudge backports)
  - CISA KEV CSV (actively exploited => escalate)
  - formulae.brew.sh API (version drift for Homebrew formulas — Homebrew has
    no CVE database, so drift is reported as its own class, not as a CVE)

Design invariants (each decision exists because the alternative breaks):
  - Diff-only alerting: a tool that cries every day gets ignored; silence means
    "nothing new", and every run still prints a coverage/doctor header.
  - Watermark advances only when every source succeeded: a failed fetch that
    advanced the watermark would hide future CVEs forever.
  - Classification is a total function: every (package, advisory) pair maps to
    exactly one of [要対応]/[推奨]/[観察]/[不要] without needing CVSS data.
  - "No input path" is never machine-decided: only the owner can declare it.
  - The scanner's own death is an alert: silent failure would look like safety.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

VERSION = "0.1.0"
UA = f"secbrief/{VERSION}"
HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = {
    "state_dir": "~/.secbrief/state",
    "cache_dir": "~/.secbrief/cache",
    "alert_file": "~/.secbrief/alerts/SECBRIEF-ALERT.md",
    "output_dir": "~/.secbrief/briefings",
    "python_envs": [],                    # empty => [sys.executable]
    "deb_hosts": [],                      # [{"name": "host", "user": "me"}]
    "brew_watch": ["node", "brotli", "curl", "openssl", "python@3.14",
                   "git", "openssh", "sqlite", "zlib", "libssh"],
    "accepted": [],                       # [{"advisory_id": "...", "package": "...", "version": "..."}]
    "ignore_overrides": [],               # owner-asserted "no input path": [{"advisory_id":..., "package":...}]
    "unmonitored_surfaces": ["docker images", "browsers (Chrome/Safari)",
                             "EOL runtimes", "snap/flatpak", "global npm packages"],
    "osv_query_url": "https://api.osv.dev/v1/querybatch",
    "osv_vuln_url": "https://api.osv.dev/v1/vulns/",
    "kev_csv_url": "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
    "brew_api": "https://formulae.brew.sh/api/formula/{name}.json",
    "http_timeout": 60,
    "max_detail_fetch": 150,              # per run; the rest are deferred to the next run
    "detail_cache_ttl": 86400,            # refresh advisory details at least daily
    "deb_batch_size": 100,                # querybatch chunk (OSV hard cap is 1000 queries)
    "detail_sleep": 0.1,
    "anonymize_extra": [],                # [[regex, replacement], ...]
}

CLASSES = ("要対応", "要対応（緩和）", "推奨", "観察", "不要")
ALERT_CLASSES = ("要対応", "要対応（緩和）", "推奨")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


# ---------------------------------------------------------------- utilities
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path, text):
    os.makedirs(os.path.dirname(os.path.expanduser(path)), exist_ok=True)
    path = os.path.expanduser(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def fingerprint(ecosystem, package, advisory_id):
    h = hashlib.sha1(f"{ecosystem}|{package}|{advisory_id}".encode()).hexdigest()[:12]
    return f"{package}@{advisory_id}:{h}"


def fetch_url(url, timeout=30, binary=False, retries=2):
    last: Exception = RuntimeError("fetch failed before first attempt")
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            return data if binary else data.decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
    raise last


def fetch_json(url, timeout=30):
    return json.loads(fetch_url(url, timeout=timeout))


def run(cmd, timeout=120):
    """Run a subprocess, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return 127, "", str(e)


def load_config(path=None):
    path = path or os.path.join(HERE, "config.json")
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        for k, v in user.items():
            cfg[k] = v
    cfg["_config_path"] = path
    return cfg


# ---------------------------------------------------------------- inventory
def inv_pip(python):
    """Return [{name, version, ecosystem:'PyPI'}] for one python interpreter."""
    rc, out, err = run([python, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
                       timeout=180)
    if rc != 0:
        raise RuntimeError(f"pip list failed for {python}: {err.strip()[:200]}")
    items = json.loads(out or "[]")
    return [{"name": i["name"].lower(), "version": i["version"], "ecosystem": "PyPI",
             "environment": os.path.realpath(python)}
            for i in items if i.get("name") and i.get("version")]


def inv_brew(watch):
    """Return {name: installed_version} for the watch list (local macOS)."""
    rc, out, _ = run(["brew", "list", "--versions"], timeout=180)
    if rc != 0:
        raise RuntimeError("brew list failed (is Homebrew installed?)")
    installed = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            installed[parts[0]] = parts[1]
    return {n: installed[n] for n in watch if n in installed}


def parse_apt_sim(out):
    """Parse `apt-get -s upgrade` output -> {binary: candidate_version}."""
    upgradable = {}
    for line in out.splitlines():
        m = re.match(r"Inst (\S+) \[\S+\] \((\S+)", line)
        if m:
            upgradable[m.group(1)] = m.group(2)
    return upgradable


def inv_deb_host(host):
    """Return {"release", "distro", "packages", "upgradable"} over ssh.

    `apt-get -s upgrade` is collected as context only; it cannot prove an
    advisory-specific fix.
    """
    user = host.get("user")
    target = f"{user}@{host['name']}" if user else host["name"]
    ssh_opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    rc, out, err = run(["ssh"] + ssh_opts + [target,
                        "dpkg-query -W -f='${Package}\\t${Version}\\t${Source}\\n' 2>/dev/null"],
                       timeout=180)
    if rc != 0:
        raise RuntimeError(f"dpkg-query failed on {target}: {err.strip()[:200]}")
    packages = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            packages.append({"name": parts[0], "version": parts[1],
                             "source": parts[2] if len(parts) > 2 and parts[2] else parts[0]})
    rc, out, _ = run(["ssh"] + ssh_opts + [target,
                      '. /etc/os-release && echo "$VERSION_ID"'], timeout=30)
    release = out.strip() or "unknown"
    rc, out, _ = run(["ssh"] + ssh_opts + [target,
                      '. /etc/os-release && echo "$ID"'], timeout=30)
    distro = out.strip() or "ubuntu"
    rc, out, _ = run(["ssh"] + ssh_opts + [target,
                      "apt-get -s upgrade 2>/dev/null | grep '^Inst ' || true"], timeout=300)
    if rc != 0:
        raise RuntimeError(f"apt-get -s upgrade failed on {target}")
    return {"release": release, "distro": distro, "packages": packages,
            "upgradable": parse_apt_sim(out)}


def build_inventory(cfg):
    """Collect inventory. Returns (inventory dict, engine_errors list)."""
    inv = {"pypi": [], "brew": {}, "deb_hosts": {}, "errors": []}
    pythons = cfg["python_envs"] or [sys.executable]
    for py in pythons:
        try:
            inv["pypi"].extend(inv_pip(py))
        except Exception as e:
            inv["errors"].append(f"pip[{py}]: {e}")
    if sys.platform == "darwin" and shutil.which("brew"):
        try:
            inv["brew"] = inv_brew(cfg["brew_watch"])
        except Exception as e:
            inv["errors"].append(f"brew: {e}")
    for host in cfg["deb_hosts"]:
        try:
            inv["deb_hosts"][host["name"]] = inv_deb_host(host)
        except Exception as e:
            inv["errors"].append(f"deb[{host['name']}]: {e}")
    return inv, inv["errors"]


# ---------------------------------------------------------------- feeds
def osv_querybatch(queries, cfg):
    """OSV querybatch. Returns [results] aligned with queries (each: {'vulns': [...]} or {})."""
    out = []
    size = cfg["deb_batch_size"]
    timeout = max(cfg["http_timeout"], 120)  # a 100-query batch can legitimately take a while
    for i in range(0, len(queries), size):
        chunk = queries[i:i + size]
        last: Exception = RuntimeError("batch failed before first attempt")
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    cfg["osv_query_url"], data=json.dumps({"queries": chunk}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": UA})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    d = json.loads(r.read().decode())
                if d.get("next_page_token"):
                    raise RuntimeError("OSV querybatch response is paginated; refusing incomplete results")
                res = d.get("results", [])
                if any(isinstance(item, dict) and item.get("next_page_token") for item in res):
                    raise RuntimeError("OSV querybatch result is paginated; refusing incomplete results")
                if len(res) != len(chunk):
                    raise RuntimeError(f"OSV querybatch returned {len(res)} for {len(chunk)} queries")
                out.extend(res)
                break
            except Exception as e:
                last = e
                time.sleep(3 * (attempt + 1))
        else:
            raise last
    return out


def osv_vuln_detail(vid, cfg, cache=None):
    """Fetch one OSV advisory, cached by id. Returns (detail, from_cache)."""
    cache_dir = os.path.join(cfg["cache_dir"], "osv")
    os.makedirs(os.path.expanduser(cache_dir), exist_ok=True)
    cpath = os.path.join(os.path.expanduser(cache_dir), vid.replace("/", "_") + ".json")
    try:
        cache_fresh = time.time() - os.path.getmtime(cpath) <= cfg.get("detail_cache_ttl", 86400)
        if cache_fresh:
            with open(cpath, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("id") == vid:
                return d, True
    except (json.JSONDecodeError, OSError):
        pass  # missing, stale, or corrupted cache entry: refetch
    d = fetch_json(cfg["osv_vuln_url"] + vid, timeout=cfg["http_timeout"])
    with open(cpath, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False)
    return d, False


def kev_set(cfg):
    """Parse the CISA KEV CSV. Returns (set_of_cve_ids, ok_flag)."""
    text = fetch_url(cfg["kev_csv_url"], timeout=60)
    ids = set()
    for row in csv.DictReader(io.StringIO(text)):
        cve = (row.get("cveID") or "").strip()
        if cve:
            ids.add(cve)
    return ids, True


def brew_latest(name, cfg):
    """Latest stable version of a Homebrew formula, or None."""
    d = fetch_json(cfg["brew_api"].format(name=name), timeout=cfg["http_timeout"])
    return (d.get("versions") or {}).get("stable")


# ---------------------------------------------------------------- matching
def extract_cve(vuln):
    ids = [vuln.get("id", "")] + [a for a in vuln.get("aliases", []) if isinstance(a, str)]
    for i in ids:
        m = CVE_RE.search(i)
        if m:
            return m.group(0)
    return None


def advisory_fix_version(vuln, package, release, expected_eco=None):
    """Find the fixed version for this package (optionally restricted to one
    ecosystem/release). GHSA advisories often cover several ecosystems (npm and
    pip entries share one id), so ecosystem pinning prevents picking an npm fix
    for a Python package."""
    candidates = []
    for aff in vuln.get("affected", []):
        pkg = (aff.get("package") or {})
        pname = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        if pname != package:
            continue
        if expected_eco and eco != expected_eco:
            continue
        candidates.append((eco, aff))
    if not candidates:
        return None
    best = None
    for eco, aff in candidates:
        if release and release != "unknown" and eco == release:
            best = aff  # release-exact entry wins
            break
        if best is None:
            best = aff
    if not best:
        return None
    for rng in best.get("ranges", []):
        for ev in rng.get("events", []):
            if "fixed" in ev:
                return ev["fixed"]
    return None


def deb_version_lt(installed, fixed):
    """Use dpkg's Debian version ordering; unavailable comparison fails closed."""
    if not shutil.which("dpkg"):
        return False
    rc, _, _ = run(["dpkg", "--compare-versions", installed, "lt", fixed], timeout=5)
    return rc == 0


def classify(fix_available, kev, severity):
    """Total classification function. Every case maps to exactly one class.

    fix_available: a fixed version exists in the advisory (distro or upstream).
    kev: the CVE is in CISA's actively-exploited catalog.
    severity: OSV/GHSA severity string or None (never gates the class).
    """
    if fix_available:
        if kev:
            return "要対応"
        return "推奨"
    # no fix yet
    if kev:
        return "要対応（緩和）"
    return "観察"


def match_inventory(inv, cfg, kev_ids, fetch_detail):
    """Match inventory against OSV. Returns (findings, coverage).

    findings: list of dicts with gate fields filled (advisory_id, package,
    installed_version, fix, kev, class, reason, ecosystem, host, cve, severity,
    source_url, fingerprint).
    """
    findings = []
    cov = {"queries": 0, "advisories_fetched": 0, "deferred": 0, "cap_hit": False,
           "gate_dropped": 0, "clean_packages": 0}
    cap = cfg["max_detail_fetch"]

    def get_detail(vid):
        """Fetch one advisory. Cache hits are free; only real fetches count
        against the per-run cap (otherwise repeats would starve fresh ids).
        Returns the detail dict, or None when deferred/failed (already counted)."""
        cache_path = os.path.join(os.path.expanduser(cfg["cache_dir"]), "osv", vid.replace("/", "_") + ".json")
        if cov["advisories_fetched"] >= cap:
            try:
                fresh = time.time() - os.path.getmtime(cache_path) <= cfg.get("detail_cache_ttl", 86400)
                with open(cache_path, encoding="utf-8") as f:
                    cached_detail = json.load(f)
                if fresh and cached_detail.get("id") == vid:
                    return cached_detail
            except (OSError, ValueError):
                pass
            cov["deferred"] += 1
            cov["cap_hit"] = True
            return None
        try:
            d, cached = fetch_detail(vid, cfg)
        except Exception:
            cov["deferred"] += 1
            cov["fetch_errors"] = cov.get("fetch_errors", 0) + 1
            return None
        if not cached:
            cov["advisories_fetched"] += 1
            time.sleep(cfg.get("detail_sleep", 0.1))
        return d

    # --- PyPI (local python envs) — purl queries keep results ecosystem-exact ---
    if inv["pypi"]:
        queries = [{"package": {"purl": f"pkg:pypi/{i['name']}@{i['version']}"}}
                   for i in inv["pypi"]]
        cov["queries"] += len(queries)
        try:
            results = osv_querybatch(queries, cfg)
        except Exception as e:
            inv["errors"].append(f"osv[PyPI]: {e}")
            results = None
        if results is not None:
            seen_pairs = set()
            for item, res in zip(inv["pypi"], results):
                if not res.get("vulns"):
                    cov["clean_packages"] += 1
                    continue
                seen_pairs.add((item["name"], item["version"]))
                for v in res["vulns"]:
                    vid = v.get("id")
                    if not vid:
                        continue
                    detail = get_detail(vid)
                    if detail is None:
                        continue
                    eco_ok = any((a.get("package") or {}).get("ecosystem", "") == "PyPI"
                                 for a in detail.get("affected", []))
                    if not eco_ok:
                        continue  # name collision in another ecosystem
                    fixed = advisory_fix_version(detail, item["name"], None,
                                                 expected_eco="PyPI")
                    cve = extract_cve(detail)
                    kev = bool(cve and cve in kev_ids)
                    sev = (detail.get("database_specific") or {}).get("severity")
                    cls = classify(fixed is not None, kev, sev)
                    why = f"fix={'あり(' + fixed + ')' if fixed else 'なし'} / KEV={kev}"
                    fp = fingerprint("PyPI:" + item.get("environment", "local"), item["name"], vid)
                    findings.append({
                        "fingerprint": fp, "class": cls, "reason": why,
                        "ecosystem": "PyPI", "host": item.get("environment", "local"), "package": item["name"],
                        "installed_version": item["version"], "advisory_id": vid,
                        "cve": cve, "fix": fixed or "なし", "kev": kev,
                        "severity": sev or "未取得",
                        "summary": (detail.get("summary") or detail.get("details") or "")[:200],
                        "source_url": f"https://osv.dev/vulnerability/{vid}",
                    })

    # --- deb hosts (ssh): only exact distro advisory details prove fixes ---
    # Generic apt candidates are useful context but are not advisory evidence.
    for host_name, host_inv in inv["deb_hosts"].items():
        rel = host_inv["release"]
        distro = host_inv.get("distro", "ubuntu")
        pkgs = host_inv["packages"]
        queries = [{"package": {"purl": f"pkg:deb/{distro}/{p['source']}@{p['version']}"}}
                   for p in pkgs]
        cov["queries"] += len(queries)
        try:
            results = osv_querybatch(queries, cfg)
        except Exception as e:
            inv["errors"].append(f"osv[deb:{host_name}]: {e}")
            results = None
        if results is None:
            continue
        adv_sources = {}
        capped = {}
        OSV_CAP = 1000  # querybatch truncates at 1000 vulns/query (observed)
        for pkg, res in zip(pkgs, results):
            vulns = res.get("vulns") or []
            if not vulns:
                cov["clean_packages"] += 1
                continue
            if len(vulns) >= OSV_CAP:
                # The advisory list may be truncated; do not infer fixes from it.
                capped[pkg["source"]] = sorted((p["name"], p["version"]) for p in pkgs
                                               if p["source"] == pkg["source"])
                continue
            for v in vulns:
                vid = v.get("id")
                if vid:
                    adv_sources.setdefault(vid, set()).add(pkg["source"])
        cov["capped_packages"] = cov.get("capped_packages", []) + [
            f"{host_name}:{s}" for s in sorted(capped)]
        for src, affected in capped.items():
            cls = classify(False, False, None)
            ver_disp = ", ".join(f"{n}={v}" for n, v in affected[:5])
            if len(affected) > 5:
                ver_disp += f" ほか{len(affected) - 5}件"
            fix = "判定不能（OSV上限）"
            findings.append({
                "fingerprint": fingerprint(f"deb:{host_name}", "cap", f"OSV:cap:{src}"),
                "class": cls,
                "reason": f"fix={fix} / OSV上限超え(1000+)でadvisory列挙不能・KEV判定不可",
                "ecosystem": f"deb:{rel}", "host": host_name,
                "package": src, "installed_version": ver_disp,
                "advisory_id": f"OSV:cap:{src}", "cve": None, "fix": fix,
                "kev": False, "severity": "判定不能",
                "summary": "影響advisoryがOSV querybatch上限(1000)超過で列挙不能。",
                "source_url": f"https://launchpad.net/ubuntu/+source/{src}",
            })
        if not adv_sources:
            continue
        for vid, sources in adv_sources.items():
            m = CVE_RE.search(vid)
            detail = get_detail(vid)
            if detail and not m:
                aliases = detail.get("aliases", [])
                m = CVE_RE.search(" ".join([detail.get("id", "")] +
                                           [a for a in aliases if isinstance(a, str)]))
            cve = m.group(0) if m else None
            kev = bool(cve and cve in kev_ids)
            affected = sorted((p["name"], p["version"]) for p in pkgs
                              if p["source"] in sources)
            distro = host_inv.get("distro", "unknown").lower()
            eco = (f"Ubuntu:{rel}:LTS" if distro == "ubuntu" else
                   f"Debian:{rel}" if distro == "debian" else "")
            source = next(iter(sources)) if len(sources) == 1 else None
            exact_affected = bool(detail and eco and source and any(
                (a.get("package") or {}).get("name") == source and
                (a.get("package") or {}).get("ecosystem") == eco
                for a in detail.get("affected", [])))
            fixed = (advisory_fix_version(detail, source, eco, expected_eco=eco)
                     if exact_affected else None)
            proven_fixed = bool(fixed and affected and all(deb_version_lt(v, fixed)
                                                           for _, v in affected))
            if proven_fixed:
                fix = f"あり(OSV固定版 {fixed})"
            elif not exact_affected:
                fix = "判定不能（OSV詳細/source/ecosystem未確認）"
            elif fixed:
                fix = "判定不能（OSV固定版/比較を確認できず）"
            else:
                fix = "なし"
            cls = classify(proven_fixed, kev, None)
            ver_disp = ", ".join(f"{n}={v}" for n, v in affected[:5])
            if len(affected) > 5:
                ver_disp += f" ほか{len(affected) - 5}件"

            src_disp = ", ".join(sorted(sources)[:5])
            if len(sources) > 5:
                src_disp += f" ほか{len(sources) - 5}件"
            findings.append({
                "fingerprint": fingerprint(f"deb:{host_name}", "host", vid),
                "class": cls,
                "reason": f"fix={fix} / KEV={kev}",
                "ecosystem": f"deb:{rel}", "host": host_name,
                "package": src_disp, "installed_version": ver_disp,
                "advisory_id": vid, "cve": cve, "fix": fix, "kev": kev,
                "severity": "未取得",
                "summary": (detail.get("summary") or "")[:200] if detail else "",
                "source_url": f"https://osv.dev/vulnerability/{vid}",
            })

    # --- brew drift (not a CVE class; separate section) ---
    drift = []
    if inv["brew"]:
        stale = False
        for name, installed in inv["brew"].items():
            try:
                latest = brew_latest(name, cfg)
            except Exception:
                stale = True
                latest = None
            if latest is None:
                stale = True
                drift.append({"name": name, "installed": installed,
                              "latest": "判定不能（索引取得失敗）"})
            elif latest != installed:
                drift.append({"name": name, "installed": installed, "latest": latest})
        cov["brew_stale_index"] = stale
    return findings, drift, cov


def apply_gate(findings):
    """Output gate: drop any finding missing a machine-verified field.

    Returns (kept, dropped_count). A line without advisory_id, installed
    version, fix status or KEV flag must never reach the owner — an
    unverifiable claim is indistinguishable from a hallucination.
    """
    kept, dropped = [], 0
    for f in findings:
        if not (f.get("advisory_id") and f.get("installed_version")
                and f.get("fix") is not None and isinstance(f.get("kev"), bool)
                and f.get("fingerprint") and f.get("class") in CLASSES):
            dropped += 1
            continue
        kept.append(f)
    return kept, dropped


# ---------------------------------------------------------------- accepted / state
def accepted_map(cfg):
    out = set()
    for a in cfg.get("accepted", []):
        out.add((a.get("advisory_id"), a.get("package"), a.get("version")))
    return out


def is_accepted(f, cfg, kev_ids):
    """Accepted items stay suppressed unless the CVE entered KEV (auto-unaccept)."""
    cve = f.get("cve")
    if cve and cve in kev_ids:
        return False
    key = (f.get("advisory_id"), f.get("package"), f.get("installed_version"))
    return key in accepted_map(cfg)


def ignore_hit(f, cfg):
    for o in cfg.get("ignore_overrides", []):
        if o.get("advisory_id") == f.get("advisory_id") and o.get("package") == f.get("package"):
            return True
    return False


def load_state(cfg):
    path = os.path.join(os.path.expanduser(cfg["state_dir"]), "state.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"fingerprints": {}, "last_full_success": None, "baseline": False}


def save_state(cfg, state):
    atomic_write(os.path.join(cfg["state_dir"], "state.json"),
                 json.dumps(state, ensure_ascii=False, indent=1))


def diff_findings(findings, state, cfg, kev_ids):
    """Split findings into (new_alerts, changed, unchanged, first_run).

    New = fingerprint unseen, or fix-state/class changed (e.g. fix published,
    KEV escalation). Accepted items are shown but never alert.
    """
    first = not state.get("baseline")
    new_alerts, changed, unchanged = [], [], []
    prev = state.get("fingerprints", {})
    for f in findings:
        fp = f["fingerprint"]
        old = prev.get(fp)
        sig = (f["class"], f["fix"], f["kev"], f.get("installed_version"), f.get("severity"), f.get("summary"))
        old_sig = (old.get("class"), old.get("fix"), old.get("kev"), old.get("installed_version"),
                   old.get("severity"), old.get("summary")) if old else None
        acc = is_accepted(f, cfg, kev_ids) or ignore_hit(f, cfg)
        if acc:
            f["class"] = f["class"] + "（accepted）"
            unchanged.append(f)
            continue
        if old is None:
            if first:
                unchanged.append(f)
            elif f["class"] in ALERT_CLASSES:
                new_alerts.append(f)
            else:
                unchanged.append(f)
        elif sig != old_sig:
            if f["class"] in ALERT_CLASSES:
                new_alerts.append(f)
            else:
                changed.append(f)
        else:
            unchanged.append(f)
    return new_alerts, changed, unchanged, first


# ---------------------------------------------------------------- report
def anonymize(text, cfg, inv):
    for i, host in enumerate(sorted(cfg.get("deb_hosts", []), key=lambda h: h["name"]), 1):
        text = re.sub(r"(?<![\w-])" + re.escape(host["name"]) + r"(?![\w-])", f"host-{i}", text)
        if host.get("user"):
            text = re.sub(r"(?<![\w.-])" + re.escape(host["user"]) + r"(?![\w.-])", "<USER>", text)
    home = os.path.expanduser("~")
    if home and home != "/":
        text = text.replace(home, "~")
    text = re.sub(r"/home/(?:[A-Za-z0-9_.-]+|<USER>)", "~", text)
    text = re.sub(r"/Users/(?:[A-Za-z0-9_.-]+|<USER>)", "~", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", text)
    for pat, rep in cfg.get("anonymize_extra", []):
        text = re.sub(pat, rep, text)
    return text


def _group_deb_rows(items):
    """Collapse per-advisory rows sharing (host, package, fix) into one row that
    lists every advisory id — a pending distro upgrade fixes a batch of CVEs at
    once, so one row per (package, fix) is the honest unit of work. Gate fields
    stay verifiable: all advisory ids remain in the line."""
    groups, order = {}, []
    for f in items:
        key = (f["host"], f["package"], f["fix"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    rows = []
    for key in order:
        fs = sorted(groups[key], key=lambda x: x["advisory_id"])
        base = fs[0]
        ids = [f["advisory_id"] for f in fs]
        id_disp = ", ".join(ids[:8])
        if len(ids) > 8:
            id_disp += f" ほか{len(ids) - 8}件"
        kev = any(f.get("kev") for f in fs)
        rows.append(
            f"- [{base['class']}] {base['package']} {base['installed_version']} "
            f"→ fix: {base['fix']} | {len(ids)} advisories: {id_disp}"
            f"{' ★KEV' if kev else ''} | {base['host']}")
        rows.append(f"  - 出典: {base['source_url']}")
    return rows


def render_briefing(findings, drift, cov, inv, cfg, errors, run_ts, first):
    """Render briefing.md. Every finding line passes the output gate already."""
    lines = [f"# secbrief briefing — {run_ts}", ""]
    # doctor / coverage header
    lines.append("## coverage / doctor")
    lines.append(f"- engines: pypi={len(inv['pypi'])} pkgs, "
                 f"deb_hosts={list(inv['deb_hosts'].keys()) or 'none'}, "
                 f"brew={len(inv['brew'])} watched")
    lines.append(f"- osv queries: {cov['queries']} | advisories fetched: "
                 f"{cov['advisories_fetched']} | deferred: {cov['deferred']} | "
                 f"clean packages: {cov['clean_packages']}")
    lines.append(f"- gate dropped (unverifiable lines): {cov.get('gate_dropped', 0)}")
    if (cov.get("fetch_errors") or cov.get("deferred") or cov.get("cap_hit") or
            cov.get("capped_packages") or cov.get("gate_dropped")):
        lines.append("- **DEGRADED — coverage incomplete; not a full-success scan**")
    if cov.get("brew_stale_index"):
        lines.append("- brew index: STALE — drift verdicts are 判定不能")
    if cov.get("capped_packages"):
        lines.append(f"- OSV 1000-cap (advisory list truncated; fix status unknown): "
                     + ", ".join(cov["capped_packages"]))
    if errors:
        lines.append(f"- **DEGRADED — incomplete scan ({len(errors)} errors): do not treat as full-success**")
        for e in errors:
            lines.append(f"  - {e}")
    lines.append(f"- not monitored (by design, review quarterly): "
                 + ", ".join(cfg["unmonitored_surfaces"]))
    lines.append("")
    if first:
        lines.append("> 初回実行＝ベースライン作成。新規警報は次回から。")
        lines.append("")

    def render_one(f):
        kev = " ★KEV" if f.get("kev") else ""
        sev = f["severity"] if f["severity"] != "未取得" else "重要度未取得"
        out = (f"- [{f['class']}] {f['package']} {f['installed_version']} "
               f"→ fix: {f['fix']} | {f['advisory_id']}"
               f"{' (' + f['cve'] + ')' if f.get('cve') else ''}{kev} | {sev} | {f['host']}")
        out += "\n" + f"  - 出典: {f['source_url']}"
        if f.get("summary"):
            out += "\n" + f"  - {f['summary']}"
        if f["class"] == "要対応（緩和）":
            out += "\n" + "  - 緩和策: fix未提供。該当サービスへの外部入力を遮断し、修正版の公開を待つこと"
        return out

    def section(title, items):
        if not items:
            return
        lines.append(f"## {title}")
        deb = [f for f in items if f.get("ecosystem", "").startswith("deb:")]
        other = [f for f in items if not f.get("ecosystem", "").startswith("deb:")]
        if title in ("推奨", "観察"):
            if deb:
                lines.extend(_group_deb_rows(deb))
                lines.append("")
        else:
            # 要対応: every line matters — render individually, never grouped away
            other = other + deb
        for f in sorted(other, key=lambda x: (not x.get("kev"), x["package"])):
            lines.append(render_one(f))
        lines.append("")

    section("要対応", [f for f in findings if f["class"].startswith("要対応")])
    section("推奨", [f for f in findings if f["class"] == "推奨"])
    section("観察", [f for f in findings if f["class"] == "観察"])
    section("不要（記録）", [f for f in findings if f["class"] == "不要"])
    if drift:
        lines.append("## 更新遅れ（Homebrew drift — CVEではなく版差）")
        for d in drift:
            lines.append(f"- {d['name']}: {d['installed']} → {d['latest']}")
        lines.append("")
    if cov.get("gate_dropped"):
        lines.append(f"> 出力ゲートにより {cov['gate_dropped']} 行を破棄（検証不能な行は表示しない）")
    return "\n".join(lines) + "\n"


def render_alert(new_alerts, run_ts, briefing_path):
    degraded = any(f.get("class") == "点検失敗（degraded）" for f in new_alerts)
    lines = [f"## secbrief alert{' — DEGRADED' if degraded else ''} — {run_ts}", ""]
    must = [f for f in new_alerts if f["class"].startswith("要対応")]
    rec = [f for f in new_alerts if f["class"] == "推奨"]
    for f in sorted(must, key=lambda x: (x["class"] != "要対応", x["package"])):
        kev = " ★KEV" if f.get("kev") else ""
        lines.append(f"- [{f['class']}] {f['package']} {f['installed_version']} "
                     f"→ fix: {f['fix']} | {f['advisory_id']}{kev} | {f['host']}")
        lines.append(f"  - {f['source_url']}")
    deb_rec = [f for f in rec if f.get("ecosystem", "").startswith("deb:")]
    other_rec = [f for f in rec if not f.get("ecosystem", "").startswith("deb:")]
    if deb_rec:
        lines.append("")
        lines.append("### 推奨（distroアップデート待ち）")
        lines.extend(_group_deb_rows(deb_rec))
    for f in sorted(other_rec, key=lambda x: x["package"]):
        lines.append(f"- [推奨] {f['package']} {f['installed_version']} "
                     f"→ fix: {f['fix']} | {f['advisory_id']} | {f['host']}")
        lines.append(f"  - {f['source_url']}")
    lines.append("")
    lines.append(f"全文: {briefing_path}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- paste pack
def build_paste_pack(briefing_path, cfg, out_path):
    prompt_path = os.path.join(HERE, "PROMPT.md")
    if os.path.exists(prompt_path):
        with open(prompt_path, encoding="utf-8") as f:
            prompt = f.read()
    else:
        prompt = "(PROMPT.mdが見つかりません。それでも以下のブリーフィングの事実のみで説明してください)\n"
    with open(briefing_path, encoding="utf-8") as f:
        body = f.read()
    if cfg.get("paste_anonymize", True):
        body = anonymize(body, cfg, {})
    pack = prompt + "\n\n---\n\n# 環境ブリーフィング（機械生成・事実のみ）\n\n" + body
    atomic_write(out_path, pack)
    return out_path


# ---------------------------------------------------------------- main run
def cmd_run(cfg, baseline=False, as_anon=False):
    run_ts = now_iso()
    state = load_state(cfg)
    first = not state.get("baseline")
    inv, errors = build_inventory(cfg)

    kev_ids, kev_ok = set(), False
    try:
        kev_ids, kev_ok = kev_set(cfg)
    except Exception as e:
        errors.append(f"kev: {e}")

    findings, drift, cov = match_inventory(inv, cfg, kev_ids, osv_vuln_detail)
    kept, dropped = apply_gate(findings)
    cov["gate_dropped"] = dropped
    all_show = kept

    new_alerts, changed, unchanged, first_run = diff_findings(all_show, state, cfg, kev_ids)

    complete = (not errors and kev_ok and not cov.get("fetch_errors") and
                not cov.get("deferred") and not cov.get("cap_hit") and
                not cov.get("capped_packages") and not cov.get("brew_stale_index") and not dropped)
    engines_ok = complete
    briefing = render_briefing(all_show, drift, cov, inv, cfg, errors, run_ts,
                               first or first_run)
    if as_anon:
        briefing = anonymize(briefing, cfg, inv)

    out_dir = os.path.expanduser(cfg["output_dir"])
    os.makedirs(out_dir, exist_ok=True)
    bpath = os.path.join(out_dir, "briefing.md")
    atomic_write(bpath, briefing)

    # state advances only when every source succeeded (invariant §7.3)
    if engines_ok:
        for f in all_show:
            state["fingerprints"][f["fingerprint"]] = {
                "class": f["class"].replace("（accepted）", ""),
                "fix": f["fix"], "kev": f["kev"], "installed_version": f.get("installed_version"),
                "severity": f.get("severity"), "summary": f.get("summary"), "last_seen": run_ts}
        state["baseline"] = True
        state["last_full_success"] = run_ts
        save_state(cfg, state)
    else:
        state["last_degraded"] = run_ts
        save_state(cfg, state)
        # degraded: state NOT advanced; alert so silence can't fake safety
        alert = render_alert([{"class": "点検失敗（degraded）", "package": "secbrief",
                               "installed_version": VERSION, "fix": "-", "advisory_id": "-",
                               "kev": False, "host": "local", "source_url": bpath}],
                             run_ts, bpath)
        apath = os.path.expanduser(cfg["alert_file"])
        os.makedirs(os.path.dirname(apath), exist_ok=True)
        with open(apath, "a", encoding="utf-8") as f:
            f.write(alert)

    if new_alerts and not baseline:
        alert = render_alert(new_alerts, run_ts, bpath)
        apath = os.path.expanduser(cfg["alert_file"])
        os.makedirs(os.path.dirname(apath), exist_ok=True)
        with open(apath, "a", encoding="utf-8") as f:
            f.write(alert)

    print(f"briefing: {bpath}")
    n = lambda c: sum(1 for f in all_show if f["class"].replace("（accepted）", "") == c)
    print(f"findings: 要対応={n('要対応')+n('要対応（緩和）')} "
          f"推奨={n('推奨')} 観察={n('観察')} 不要={n('不要')} | "
          f"new alerts: {len(new_alerts)} | degraded: {not engines_ok}")
    return 0 if engines_ok else 2


def cmd_doctor(cfg):
    state = load_state(cfg)
    print(f"last full success: {state.get('last_full_success')}")
    print(f"last degraded:     {state.get('last_degraded')}")
    print(f"baseline:          {state.get('baseline')}")
    print(f"tracked fingerprints: {len(state.get('fingerprints', {}))}")
    apath = os.path.expanduser(cfg["alert_file"])
    if os.path.exists(apath):
        age = time.time() - os.path.getmtime(apath)
        print(f"alert file: {apath} (updated {age/3600:.1f}h ago)")
    else:
        print("alert file: none yet")
    print("cron check: the scheduler must call `secbrief.py run`; a fresh "
          "briefing mtime older than 2x your interval means the job is dead.")
    return 0


def cmd_init(cfg_path):
    example = os.path.join(HERE, "config.example.json")
    if os.path.exists(cfg_path):
        print(f"config exists: {cfg_path}")
        return 0
    shutil.copy(example, cfg_path)
    print(f"config created: {cfg_path}")
    print("next: edit deb_hosts / python_envs / brew_watch, then run: "
          "python3 secbrief.py run --baseline")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="secbrief", description=(__doc__ or "").splitlines()[0])
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=os.path.join(HERE, "config.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="collect, match, write briefing, alert on diffs",
                           parents=[common])
    p_run.add_argument("--baseline", action="store_true", help="first run: no alerts")
    p_run.add_argument("--anonymize", action="store_true",
                       help="strip hostnames/IPs/user paths from the briefing")
    sub.add_parser("doctor", help="show scanner health and coverage state", parents=[common])
    sub.add_parser("init", help="create config.json from the example", parents=[common])
    p_paste = sub.add_parser("paste", help="build a single-file pack for any LLM",
                             parents=[common])
    p_paste.add_argument("--no-anonymize", action="store_false", dest="anonymize",
                         help="include configured host and user identifiers")
    p_paste.set_defaults(anonymize=True)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    if args.cmd == "run":
        return cmd_run(cfg, baseline=args.baseline, as_anon=args.anonymize)
    if args.cmd == "doctor":
        return cmd_doctor(cfg)
    if args.cmd == "init":
        return cmd_init(args.config)
    if args.cmd == "paste":
        out_dir = os.path.expanduser(cfg["output_dir"])
        bpath = os.path.join(out_dir, "briefing.md")
        if not os.path.exists(bpath):
            print("no briefing yet — run `secbrief.py run` first", file=sys.stderr)
            return 1
        out = os.path.join(out_dir, "secbrief-paste.md")
        paste_cfg = dict(cfg)
        paste_cfg["paste_anonymize"] = args.anonymize
        print(build_paste_pack(bpath, paste_cfg, out))
        return 0
    return 1


def cfg_path_default():
    return os.path.join(HERE, "config.json")


if __name__ == "__main__":
    sys.exit(main())
