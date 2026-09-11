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
