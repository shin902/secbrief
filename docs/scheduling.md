# Scheduling secbrief

Default cadence: every 6 hours. 12/24h also work; nothing in secbrief assumes
a particular interval. `doctor` uses the briefing file's age against 2× your
interval to detect a dead scheduler.

## macOS (launchd)

Save as `~/Library/LaunchAgents/com.secbrief.run.plist` (replace `/path/to/secbrief`
and note launchd needs absolute paths — no `~` inside the plist):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.secbrief.run</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/path/to/secbrief/secbrief.py</string>
    <string>run</string>
  </array>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>17</integer></dict>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>17</integer></dict>
    <dict><key>Hour</key><integer>15</integer><key>Minute</key><integer>17</integer></dict>
    <dict><key>Hour</key><integer>21</integer><key>Minute</key><integer>17</integer></dict>
  </array>
  <key>StandardOutPath</key><string>/tmp/secbrief.out</string>
  <key>StandardErrorPath</key><string>/tmp/secbrief.err</string>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.secbrief.run.plist
launchctl kickstart gui/$(id -u)/com.secbrief.run   # test-fire once
```

## Linux (cron)

```
17 3,9,15,21 * * * cd /path/to/secbrief && /usr/bin/python3 secbrief.py run >> /tmp/secbrief.out 2>&1
```

## Alerting to a human

secbrief appends new findings to `alerts/SECBRIEF-ALERT.md` and prints a summary
to stdout. Wire whatever you already read to that file, e.g. a launchd/cron job
that mails or pushes when the file's mtime advances:

```bash
[ "$(stat -f %m ~/.secbrief/alerts/SECBRIEF-ALERT.md)" -gt "$LAST_SEEN" ] && your-notify.sh
```

## Death check (the one that matters)

A scanner that stops running looks identical to "no vulnerabilities". Check
weekly (or from any watchdog you already have):

```bash
python3 /path/to/secbrief/secbrief.py doctor
# alert file / briefing mtime older than 2x your interval => scheduler is dead
```

Or let any existing uptime/health monitor watch `briefings/briefing.md` mtime.
