# Security Policy

## What secbrief does

Reads your package inventory (pip/dpkg/Homebrew), matches it against three
official free feeds (OSV.dev, CISA KEV, formulae.brew.sh), and writes a local
markdown briefing. It changes nothing on your machines.

## What secbrief deliberately does not do

- **No automatic patching.** Nothing is upgraded, restarted, or removed, ever.
- **No outbound data.** The only network traffic is: fetches FROM the three
  feeds, and SSH to the hosts you configured (read-only `dpkg-query`). The
  briefing/alerts never leave the machine unless you move them.
- **No secrets in the repo or config.** `config.json` holds hostnames and
  paths only. `.gitignore` excludes it, plus `state/`, `cache/`, `alerts/`.
- **No shell from advisory text.** CVE descriptions are stored data. The
  output gate requires machine-verified fields on every report line, so a
  poisoned advisory cannot inject a fake finding, and `PROMPT.md`/`AGENTS.md`
  bind any LLM step to "explain, don't execute".

## Trust model

- The matcher is deterministic Python you can read in one file (`secbrief.py`).
- The LLM (if you use one) only ever sees a briefing that already passed the
  gate, plus a prompt that forbids inventing facts and executing commands.
- `accepted` suppressions auto-cancel when the CVE enters CISA KEV — an
  accepted risk can never quietly stay accepted while it is being exploited.

## Known limitations

See README ("Honest limitations"). In short: container images, browsers, EOL
runtimes and similar surfaces are listed as unmonitored in every briefing
header; feeds can lag; the tool reports exposure of *packages*, not of
*running services*.

## Reporting a vulnerability

Open a GitHub issue with minimal detail, or contact the maintainers privately
if the issue would expose an exploitable path in a common deployment. Please
include: secbrief version, the affected code path, and (if possible) an
offline repro using the test fixtures.
