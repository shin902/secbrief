# secbrief-extra

A dependency-free Python companion for explicit `npm` v2/v3 and Composer lockfiles, plus static Electron `app.asar` metadata inspection. It does not modify the referenced secbrief project or run advisory-provided commands.

## Run

```sh
python3 secbrief_extra.py inventory --lockfile ./package-lock.json --lockfile ./composer.lock --asar ./resources/app.asar --output ./secbrief-extra-out
python3 secbrief_extra.py run --lockfile ./package-lock.json --lockfile ./composer.lock --asar ./resources/app.asar --output ./secbrief-extra-out
python3 secbrief_extra.py run --lockfile ./package-lock.json --online --output ./secbrief-extra-out
python3 secbrief_extra.py handoff --report ./secbrief-extra-out/report.json --output ./secbrief-extra-out/handoff.json
python3 secbrief_extra.py doctor --output ./secbrief-extra-out
```

`inventory` and default `run` are offline. `--online` explicitly sends package names and versions in OSV querybatch requests and retrieves advisory details plus CISA KEV. Results live in report.json/report.md; alerts.json is a local diff envelope. Exit codes: `0` no observed change (also inventory-only), `10` changed findings since a successful baseline, `2` degraded scan/input errors. Degraded or inventory-only runs never advance diff state. Run lock serializes state updates.

ASAR inspection parses only a capped header and the indexed `package.json` resource (maximum 1 MiB); it does not extract or execute files. ASAR application package version is recorded as the installed application version. Electron and embedded Node versions remain `null` unless later proven by a separate source; no Node-major heuristic or upstream release claim is used. External/unpacked package resources produce unknown.

An OSV exact-version match is reported as affected. Fix-version strings are advisory metadata hints scoped to the exact package/ecosystem; they do not imply a tested upgrade or calculate version ranges. KEV is `null` when it cannot be established. Any query/detail/KEV failure degrades the run and preserves prior state. Source paths and package identities are retained; treat reports and handoffs as sensitive. Handoff tasks require human approval and ask for a plan only; this tool never executes remediation.

## Limits

No lockfile discovery, package-manager resolution, OS-level inventory, Electron runtime execution/probing, release-index comparison, auto-remediation, email/webhook delivery, scheduling, or claim of universal vulnerability coverage. Inventory errors are surfaced, not interpreted as clean. `fcntl` locking targets Unix-like hosts. No claims are made that this replaces secbrief or fixes its behaviors.

## Tests

```sh
python3 -m unittest -v
```
