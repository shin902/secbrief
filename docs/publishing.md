# Publishing checklist (for the maintainer)

The repo is intentionally push-ready with **no remote configured**. Publishing
is a separate, deliberate step.

## Pre-flight (all done — re-verify after any change)

```bash
# 1. offline tests
python3 -m unittest tests.test_secbrief

# 2. personal-data scan (must return nothing; use YOUR own names/IPs here)
git grep -nE "([0-9]{1,3}\.){3}[0-9]{1,3}" -- . | grep -vE "192\.0\.2\.10|127\.0\.0\.1|0\.0\.0\.0"
git grep -inE "<your-username>|<your-hostname>|<your-mail-domain>" -- .

# 3. nothing private tracked
git status --short          # config.json / state/ / cache/ / alerts/ must stay ignored
git ls-files | grep -E "config\.json$|state/|cache/|alerts/" && echo "LEAK" || echo "OK"

# 4. author is anonymous
git log --format='%an <%ae>' | sort -u
```

## Publish (when approved)

```bash
gh repo create secbrief --public --source=. --remote=origin   # creates only
git push -u origin main
```

Replace `secbrief` with `<owner>/secbrief` to publish under an organization.

## Notes

- License: MIT, "secbrief contributors". No personal names.
- Data: fetched at runtime from OSV.dev (CC-BY-4.0) and CISA KEV (public
  domain); nothing is redistributed by the repo.
- No secrets exist in this project: all three sources are keyless.
