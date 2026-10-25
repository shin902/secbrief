# secbrief-extra

A dependency-free Python companion for explicit `npm` v2/v3 and Composer lockfiles, plus static Electron `app.asar` metadata inspection. It does not modify the referenced secbrief project or run advisory-provided commands.

## Run

```sh
python3 secbrief_extra.py inventory --lockfile ./package-lock.json --lockfile ./composer.lock --asar ./resources/app.asar --output ./secbrief-extra-out
python3 secbrief_extra.py run --lockfile ./package-lock.json --lockfile ./composer.lock --asar ./resources/app.asar --output ./secbrief-extra-out
python3 secbrief_extra.py run --lockfile ./package-lock.json --online --output ./secbrief-extra-out
# Explicit runtime probe (only if binary fuse confirms runAsNode enabled)
python3 secbrief_extra.py run --asar ./resources/app.asar --electron-binary ./electron --probe-runtime --output ./secbrief-extra-out
python3 secbrief_extra.py handoff --report ./secbrief-extra-out/report.json --output ./secbrief-extra-out/handoff.json
python3 secbrief_extra.py doctor --output ./secbrief-extra-out
```

`inventory` and default `run` are offline. `--online` explicitly sends package names and versions in OSV querybatch requests and retrieves advisory details plus CISA KEV. Results live in report.json/report.md; alerts.json is a local diff envelope. Exit codes: `0` no observed change (also inventory-only), `10` changed findings since a successful baseline, `2` degraded scan/input errors. Degraded or inventory-only runs never advance diff state. Run lock serializes state updates.

ASAR inspection parses a capped header/tree (8 MiB, 100,000 entries, depth 64) and package.json resources up to 1 MiB; it does not extract or follow ASAR links. It collects exact npm package versions in the app and all `node_modules`, including nested/scoped packages, with ASAR source/location evidence. Adjacent `.unpacked` and `app/` directories are walked without following symlinks/out-of-tree paths. Reports include native-library filename inventory and best-effort dependency names from `readelf`/`objdump`/`otool`; these tools inspect files, not execute targets. JS source-map/license/version strings are candidate metadata only, not verified installed versions. Walk and byte limits apply; reports include coverage and errors.

Runtime probing is never automatic: both `--probe-runtime` and `--electron-binary PATH` are required. The tool reads the official fuse wire sentinel/version/length/state first; it invokes the binary only when the unique fuse wire reports RunAsNode enabled. Disabled, removed, malformed, missing, or ambiguous fuse state is unknown/not invoked. The opt-in process has a 10-second timeout and sanitized environment (preload/module-path variables removed), then reports only `process.versions` values with probe source. This explicit operation runs a binary supplied by the user; do not use it on untrusted executables. Fuses format reference: https://github.com/electron/electron/blob/main/docs/tutorial/fuses.md; RunAsNode index: https://github.com/electron/fuses/blob/main/src/config.ts.

An OSV exact-version match is reported as affected. Fix-version strings are advisory metadata hints scoped to the exact package/ecosystem; they do not imply a tested upgrade or calculate version ranges. KEV is `null` when it cannot be established. Any query/detail/KEV failure degrades the run and preserves prior state. Source paths and package identities are retained; treat reports and handoffs as sensitive. Handoff tasks require human approval and ask for a plan only; this tool never executes remediation.

## Limits

No lockfile discovery, package-manager resolution, full OS-level inventory, release-index comparison, auto-remediation, email/webhook delivery, scheduling, or claim of universal vulnerability coverage. Static archive/directory scans are bounded and incomplete; native dependency/version attribution and bundled JS metadata are not authoritative. Inventory errors are surfaced, not interpreted as clean. `fcntl` locking targets Unix-like hosts. No claims are made that this replaces secbrief or fixes its behaviors.

## Tests

```sh
python3 -m unittest -v
```
