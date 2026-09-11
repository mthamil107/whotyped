//go:build !linux

package check

import (
	"io"
	"io/fs"
)

// defaultFS returns nil: there is no /etc/ssh or /proc to look at, so the
// Linux probes report skip. Tests pass an fs.FS explicitly.
func defaultFS() fs.FS { return nil }

// defaultExec returns nil: no sshd, systemctl or journalctl to run.
func defaultExec() ExecFunc { return nil }

// fixPlatform cannot install anything off Linux.
func fixPlatform(_ Options, _ io.Writer) ([]Result, int) {
	return []Result{{Name: "fix", Status: StatusSkip,
		Detail: "check --fix writes /etc/ssh/sshd_config.d and /etc/audit/rules.d; Linux only",
		Fix:    "copy deploy/sshd/90-whotyped.conf and deploy/audit.rules to the target host"}}, ExitCannotRun
}
