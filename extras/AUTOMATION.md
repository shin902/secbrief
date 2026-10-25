# Secbrief automation

`cycle` is a one-shot scan. It prints a JSON result with `status` (`changed`, `nochange`, or `failed`); nonzero exit means the scan failed. No-change produces no notification or local outbox entry. The calling agent can use the result to decide whether to notify.

```sh
python3 extras/automation.py cycle --config /path/to/operator-config.json
python3 extras/automation.py agent-plan --config /path/to/operator-config.json --output review-request.json
python3 extras/automation.py plan --config /path/to/operator-config.json --name chosen-plan --output plan.json
python3 extras/automation.py execute --plan plan.json --approve REVIEWED_SHA256
```

The agent host owns scheduling and notifications (including Discord); this tool neither generates/installs schedules nor sends messages. Configure those only on the host's supported automation surface.

`agent-plan` only exports a read-only review request. Remediation remains human-gated: approve the exact plan hash once; execution runs update, optional restart, then exact version/status and readiness verification. An attempted approval cannot be reused.

Run the focused tests:

```sh
python3 -m unittest discover -s extras -p 'test_automation.py' -v
```
