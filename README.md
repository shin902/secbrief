# secbrief

**English** | [한국어](README.ko.md) | [中文](README.zh.md) | [日本語](README.ja.md)

**A daily vulnerability briefing for AI-agent-managed machines.**

You tell an AI agent "watch my machines for vulnerabilities." The agent installs
this. From then on, every few hours, a machine-generated briefing tells you what
changed and what needs you. The LLM never decides anything — it only explains.

```bash
git clone <this repo> && cd secbrief
python3 secbrief.py init        # creates config.json
$EDITOR config.json             # list your SSH hosts / python envs / brew formulas
python3 secbrief.py run --baseline   # first run: builds the baseline, no alerts
python3 secbrief.py run              # every 6h from cron/launchd; alerts on diffs
python3 secbrief.py doctor           # is the scanner healthy? when did it last succeed?
```

Setup takes about 5 minutes. No API keys, no accounts, no agent framework.

## What it does

**Sources (free, official, no keys):**
- [OSV.dev](https://osv.dev) querybatch + advisory details — matches your real
  installed versions (PyPI via purl, Ubuntu/Debian via `pkg:deb/<distro>/...`).
  Distro advisories are the truth for system packages, so backported builds
  (e.g. `1.1.0-2build2.1`) are judged correctly, not by upstream version math.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  actively exploited ⇒ the finding escalates. An item you "accepted" earlier is
  **auto-unaccepted** if its CVE later enters KEV.
- [formulae.brew.sh](https://formulae.brew.sh) — Homebrew has no CVE database,
  so formula drift is reported as its own section (更新遅れ), never as a fake CVE.

**Inventory (read-only, nothing is changed on your machines):**
- Python environments: `pip list` (any interpreters you list)
- Ubuntu/Debian hosts: `dpkg-query` over SSH (key-based)
- macOS Homebrew: `brew list --versions` for your watch list

**The briefing** (markdown, one file per run) sorts everything into four classes:

- `[要対応]` — fix published **and** CVE is in KEV. Act today.
- `[要対応（緩和）]` — actively exploited, **no fix yet**. Mitigate (cut input
  paths), then wait.
- `[推奨]` — fix published, not in KEV. Patch at your cadence.
- `[観察]` — no fix yet, not exploited. Watch. (Deliberately carries **no
  severity number**: a CVSS score on an unpatchable bug is noise, not signal.)
- plus `[不要]` rows the machine can prove are moot (distro already fixed /
  not installed), `[（accepted）]` rows you reviewed and accepted, and the brew
  drift section.

Every finding line carries the machine-verified quadruple: advisory ID,
installed version, fix version, KEV flag — with a link to the advisory.

## The rules that make it trustworthy

1. **The matcher is deterministic code, not an LLM.** Version comparison is
   where hallucinations would do real damage, so it never touches a model.
2. **Output gate.** A line missing its advisory ID / installed version / fix
   status / KEV flag cannot be emitted — unverifiable claims are dropped and
   counted. Fabricating a finding is impossible by construction.
3. **Advisory text is data, not instructions.** CVE descriptions that say
   "run this command" are quoted as text; the bundled `PROMPT.md` (for the
   explain-to-the-owner step) tells any LLM the same.
4. **Watermark advances only on full success.** A failed fetch that advanced
   the diff state would hide future CVEs forever; a degraded run instead
   raises a `点検失敗` alert. A scanner that dies silently looks like safety;
   this one refuses to.
5. **First run is a baseline.** You start with a clean slate, not 200 alerts.
6. **"No input path" is never machine-decided.** Only you can add an
   `ignore_overrides` entry. (The machine *can* prove the two mechanical cases:
   distro-fix-already-installed and not-installed.)

## The two routes

- **Route A (LLM explains):** run secbrief on cron; when the alert file gains
  content, open `briefing.md` — or `python3 secbrief.py paste` to build a
  single file (PROMPT.md + briefing) to drop into any LLM chat for a plain
  language explanation and a prioritized plan.
- **Route B (agent maintains):** hand your coding agent `AGENTS.md`; it can
  install, schedule, verify health, and prepare patch commands. It still never
  applies patches unattended — you say "やって" and run them.

## Scheduling

Every 6 hours is a good default (12/24h also fine). Example launchd plist and
cron line are in `docs/scheduling.md`. Health check: `secbrief.py doctor` — if
the briefing file's mtime is older than twice your interval, the job is dead.

## Honest limitations

- Not monitored by design (review them quarterly): container images, browsers,
  EOL runtimes, snap/flatpak, global npm packages. The briefing lists them in
  every header so "not watched" can never be forgotten.
- **OSV querybatch caps at 1000 advisories per query.** A handful of sources
  (the Linux kernel, typically) exceed that; the API returns an arbitrary
  subset, so secbrief refuses to enumerate it. Those sources get one rollup row
  judged by the distro's own pending-upgrade state (apt candidate = fix
  available), and the header names them (`OSV 1000-cap`). Per-CVE KEV
  escalation is not possible for those — the fix action (run the distro
  upgrade) is unchanged.
- Sources lag: OSV aggregates fast (usually <24h) but is not instantaneous;
  the CISA KEV catalog updates on U.S. government schedule.
- The briefing tells you *that* something needs fixing, not *how* to fix your
  particular app safely. The fix version is machine-verified; your rollback
  plan is not.
- This is a briefing tool, not a scanner appliance: it matches your *package
  inventory* against advisories. It cannot see runtime exposure (which service
  actually parses untrusted input) — that call stays with you.
- Briefing readability: per-advisory rows are kept for `[要対応]`; the large
  `[推奨]`/`[観察]` backlog is rolled up per (package, fix state) with all
  advisory ids in the line, because one `apt upgrade` resolves a batch.

## Security notes

See `SECURITY.md` (what this tool does and deliberately does not do; the
reporting policy). No secrets belong in `config.json`; `.gitignore` ships with
`config.json`, `state/`, `cache/`, `alerts/` excluded.

## Contributors

- **tenhkspark** — owner and operator of the DGX Spark cluster
- **GLM-5.3-Flash** — design, implementation, and this documentation (running locally on the cluster)
- **Qwen3.8-Flash-Next** — independent security review (running locally on the cluster)
- **Nemotron 3.5 Lightning 30B-A3B** — independent security review (running locally on the cluster)
- other local models on the DGX Spark cluster — reviews and verification

All AI contributors ran locally on the owner's hardware; no external AI services were involved.

## License

MIT. Data is fetched at runtime from public sources (OSV.dev is CC-BY-4.0,
KEV is U.S. Government public domain); secbrief redistributes none of it.
