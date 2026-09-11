#!/bin/sh
# whotyped package pre-remove (deb prerm / rpm %preun).
# Stops and disables the unit. State (/var/lib/whotyped) and the drop-ins
# written by `whotyped check --fix` are left in place: alerts are evidence,
# and removing sshd/auditd settings behind the operator's back is rude.
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop whotyped.service >/dev/null 2>&1 || true
    systemctl disable whotyped.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'
whotyped stopped and disabled. Left in place on purpose:
  /var/lib/whotyped                       state and alerts.jsonl
  /etc/ssh/sshd_config.d/90-whotyped.conf sshd LogLevel VERBOSE + AcceptEnv AI_AGENT
  /etc/audit/rules.d/90-whotyped.rules    auditd execve rule
Remove them by hand if you no longer want them.
EOF
exit 0
