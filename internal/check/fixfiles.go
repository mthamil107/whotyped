package check

// The two files `check --fix` installs. They mirror deploy/sshd/90-whotyped.conf
// and deploy/audit.rules byte for byte (a test enforces it); Go's embed
// cannot reach ../../deploy, hence the copies.

// SSHDDropInPath is where the sshd drop-in is written.
const SSHDDropInPath = "/etc/ssh/sshd_config.d/90-whotyped.conf"

// AuditRulesPath is where the audit rules are written.
const AuditRulesPath = "/etc/audit/rules.d/90-whotyped.rules"

// SSHDDropIn is the content of deploy/sshd/90-whotyped.conf.
const SSHDDropIn = `# whotyped sshd drop-in. Installed by ` + "`whotyped check --fix`" + ` as
# /etc/ssh/sshd_config.d/90-whotyped.conf; requires an
#   Include /etc/ssh/sshd_config.d/*.conf
# line near the top of /etc/ssh/sshd_config (Debian, Ubuntu, Fedora, RHEL 9
# and SUSE ship one). sshd applies the first value it sees for a keyword, so
# a LogLevel set earlier in sshd_config, or in a lower-numbered drop-in,
# wins over this file; ` + "`whotyped check`" + ` reports the effective value.
#
# Reload, never restart:  systemctl reload ssh   (or: systemctl reload sshd)

# Let clients declare an AI agent. Agents send it with ` + "`ssh -o SendEnv=AI_AGENT`" + `
# or a library's env= option; whotyped reads it from the session's environment
# and classifies the session as declared_agent (class, not a score).
AcceptEnv AI_AGENT

# VERBOSE adds "Starting session: command/shell/subsystem" and
# "Connection from ..." lines, which the rhythm and pty clue families need.
# INFO (the default) only logs authentication and disconnects.
LogLevel VERBOSE

# Optional: the client software banner ("remote software version paramiko_3.4.0")
# is logged only at DEBUG1. It enables the banner clue family (+35 for SSH
# libraries) at the cost of much chattier logs. Uncomment to opt in:
# LogLevel DEBUG1
`

// AuditRules is the content of deploy/audit.rules.
const AuditRules = `## whotyped auditd rules. Installed by ` + "`whotyped check --fix`" + ` as
## /etc/audit/rules.d/90-whotyped.rules.
##
## Records every execve by a logged-in user (auid >= 1000, i.e. a real login,
## not a system service; auid!=unset skips processes with no login session).
## The ` + "`ses=`" + ` field on each record ties the command to the SSH session that
## auditd opened at login, which is how whotyped attributes command text and
## style/flags clues to a remote session without cooperation from the client.
##
## Load without restarting auditd:  augenrules --load
## (or, on systems without augenrules: auditctl -R /etc/audit/rules.d/90-whotyped.rules)
## The key "whotyped" lets you inspect matches with:  ausearch -k whotyped
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k whotyped
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k whotyped
`

// SSHRCPath is where the sshrc declaration hook is installed. `check --fix`
// writes it only when no system sshrc exists; it never edits an existing one.
const SSHRCPath = "/etc/ssh/sshrc"

// SSHRCMarker identifies the whotyped hook inside an sshrc file.
const SSHRCMarker = "whotyped-declare"

// SSHRC is the content of deploy/sshd/sshrc.
const SSHRC = `# whotyped sshrc hook. Installed by ` + "`" + `whotyped check --fix` + "`" + ` as /etc/ssh/sshrc
# when that file does not exist yet. If you already have an /etc/ssh/sshrc,
# copy the first block below into it.
#
# sshd runs this file with /bin/sh, as the logged-in user, for every session
# (shell, command or subsystem) after the client's accepted environment is in
# place and before the session's command starts. It logs an AI_AGENT
# declaration together with the session's source address and port, so
# whotyped can label one-command-per-step agents: their commands finish long
# before a /proc scan could read the environment, and sshd itself logs
# accepted variables only at DEBUG2.
#
# The line goes to syslog facility authpriv with the tag whotyped-declare.
# It is a claim, not proof: any local user can call logger(1). whotyped only
# attaches a declaration to an SSH connection that already exists for the
# same user, address and port, and on journald it also checks the sender uid.
#
# sshd skips this file for a user who has ~/.ssh/rc (unless PermitUserRC is
# no). When this file exists sshd no longer runs xauth itself, so the second
# block does it; that block is the one documented in sshd(8).

if [ -n "${AI_AGENT:-}" ] && command -v logger >/dev/null 2>&1; then
	whotyped_agent=$(printf '%s' "$AI_AGENT" | LC_ALL=C tr -cd 'A-Za-z0-9._@:+-' | cut -c1-64)
	# SSH_CONNECTION is "client_ip client_port server_ip server_port".
	set -- ${SSH_CONNECTION:-}
	if [ -n "$whotyped_agent" ] && [ -n "${1:-}" ] && [ -n "${2:-}" ]; then
		logger -p authpriv.info -t whotyped-declare -- \
			"AI_AGENT=$whotyped_agent user=${USER:-$(id -un)} from=$1 port=$2" 2>/dev/null || :
	fi
	unset whotyped_agent
	set --
fi

if read proto cookie && [ -n "${DISPLAY:-}" ]; then
	if [ "$(echo "$DISPLAY" | cut -c1-10)" = 'localhost:' ]; then
		# X11UseLocalhost=yes
		echo add "unix:$(echo "$DISPLAY" | cut -c11-)" "$proto" "$cookie"
	else
		# X11UseLocalhost=no
		echo add "$DISPLAY" "$proto" "$cookie"
	fi | xauth -q -
fi
`
