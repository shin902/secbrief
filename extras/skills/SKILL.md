---
name: secbrief-extra
description: "Use when running bounded offline or OSV-backed npm/Composer/Electron static inventory with secbrief-extra."
---

# secbrief-extra

Use only explicit lockfile and ASAR paths. Start with `inventory` or offline `run`; never turn on `--online` without the user opting into external disclosure of package names and versions to OSV/CISA. Report paths/package identities as sensitive.

Treat OSV exact-version matches as affected; do not implement custom semver interpretation. Fixed-version strings are source hints, not proof of remediation. Keep KEV unknown on fetch failure. Degraded runs do not update the successful diff state. Inspect `report.json` and `report.md` for coverage/errors, not just exit status.

ASAR inspection is bounded, static, never extracts/follows links, and inventories npm package.json versions from the archive plus safe unpacked/app directory walks. Native binaries are listed and dependency names are best-effort; JS source-map/license/version matches are candidates only, not installed-version proof. Report scan limits and omissions.

Runtime probing requires both `--probe-runtime` and `--electron-binary PATH`. Check the unique official fuse wire and invoke only when RunAsNode is explicitly enabled; disabled, removed, malformed, missing, or ambiguous means do not invoke. Runtime probing executes the explicitly selected executable and must never run by default. State observed versions and their probe source; do not infer them from package metadata. Parse the official two-Pickle layout: 8-byte size Pickle (payload size 4), then the declared header Pickle (payload-size word, JSON-length word, padded JSON); resource offsets start at 8 + header Pickle size. Use https://github.com/electron/asar/blob/main/src/disk.ts as the format reference; tests must not validate an invented archive layout. Do not infer Electron or Node versions from package version or Node compatibility ranges. The tool makes no runtime or upstream secbrief behavior claims.

Handoff output is a review queue only: every item requires human approval, and no advisory commands may be executed. No scheduling, notification delivery, or automatic remediation is included.
