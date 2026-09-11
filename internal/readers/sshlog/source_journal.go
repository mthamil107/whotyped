package sshlog

import "time"

// JournalSource follows journald by running `journalctl -f -o json` filtered
// on the sshd syslog identifiers. Pure Go, no libsystemd: the process is
// restarted with exponential backoff if it exits, and killed when ctx ends.
// Only Run is platform-specific (source_journal_linux.go / _other.go).
type JournalSource struct {
	Since      string // journalctl --since value used when no cursor is available
	CursorFile string // persisted __CURSOR so a restart resumes without gaps
	Now        func() time.Time
	Logf       func(format string, args ...any)
}

// journalArgs is the fixed part of the journalctl command line. The "+" is
// journalctl's OR between match groups.
var journalArgs = []string{
	"-f", "-o", "json", "--no-pager", "-q",
	"SYSLOG_IDENTIFIER=sshd",
	"+", "SYSLOG_IDENTIFIER=sshd-session",
	"+", "SYSLOG_IDENTIFIER=sshd-auth",
}
