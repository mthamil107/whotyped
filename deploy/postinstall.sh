#!/bin/sh
# whotyped package post-install (deb postinst / rpm %post).
# Creates the state directory, registers the unit, enables it, but does NOT
# start it: sshd and auditd usually need `whotyped check --fix` first.
set -e

STATE_DIR=/var/lib/whotyped
CONFIG=/etc/whotyped/config.yaml

if [ ! -d "$STATE_DIR" ]; then
    mkdir -p "$STATE_DIR"
fi
chmod 0750 "$STATE_DIR"
chown root:root "$STATE_DIR" 2>/dev/null || true

if [ -d /etc/whotyped ]; then
    chmod 0755 /etc/whotyped
    [ -f "$CONFIG" ] && chmod 0640 "$CONFIG"
    mkdir -p /etc/whotyped/rules.d
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable whotyped.service >/dev/null 2>&1 || true
fi

cat <<'EOF'

whotyped installed. Before starting it:

  sudo whotyped check --fix        # sshd LogLevel VERBOSE + AcceptEnv AI_AGENT, auditd execve rule
  sudo systemctl reload ssh        # or: systemctl reload sshd
  sudo augenrules --load           # if auditd is installed
  sudo systemctl start whotyped
  whotyped simulate                # benign agent-shaped session; expects an alert

Config: /etc/whotyped/config.yaml (every key documented inline).
Alerts: /var/lib/whotyped/alerts.jsonl    Report: whotyped report --since 7d
EOF
exit 0
