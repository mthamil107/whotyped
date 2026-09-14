#!/bin/sh
# Start rsyslog, sshd and whotyped, then keep the container alive.
set -e
SSHD_LOGLEVEL="${SSHD_LOGLEVEL:-VERBOSE}"
ssh-keygen -A >/dev/null
# Root is the SSH client for every scenario: one key authorised for each lab user.
mkdir -p /root/.ssh && chmod 700 /root/.ssh
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
for u in alice bob carol dave erin frank grace; do
  install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
  install -m 600 -o "$u" -g "$u" /root/.ssh/id_ed25519.pub "/home/$u/.ssh/authorized_keys"
done
install -d -m 755 -o erin -g erin /home/erin/bin
install -m 755 -o erin -g erin /usr/local/share/whotyped-lab/claude /home/erin/bin/claude
install -m 640 -o syslog -g adm /dev/null /var/log/auth.log
if [ "${WHOTYPED_LAB_FREEZE:-0}" = "1" ]; then
  # A freeze window from one hour ago to one hour ahead, so it is active now.
  cat >> /etc/whotyped/config.yaml <<CFG
freeze_windows:
  - name: lab-freeze
    start: $(date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)
    end: $(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
    level: high
    include_declared: true
CFG
fi
rsyslogd
# Configure the host the way an operator would: check --fix writes the sshd
# drop-in (LogLevel VERBOSE, AcceptEnv AI_AGENT), the sshrc declaration hook
# and the audit rules, then runs sshd -t.
whotyped check --fix > /var/lib/whotyped/fix.txt 2>&1 || true
/usr/sbin/sshd -o "LogLevel=${SSHD_LOGLEVEL}"
whotyped check --config /etc/whotyped/config.yaml > /var/lib/whotyped/check.txt 2>&1 || true
nohup whotyped run --config /etc/whotyped/config.yaml > /var/lib/whotyped/daemon.log 2>&1 &
echo "lab ready: sshd LogLevel=${SSHD_LOGLEVEL}"
exec sleep infinity
