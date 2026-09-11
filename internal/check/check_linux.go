//go:build linux

package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultFS is the real root filesystem.
func defaultFS() fs.FS { return os.DirFS("/") }

// defaultExec runs commands with a short timeout. Output is captured; the
// command never inherits our stdin.
func defaultExec() ExecFunc {
	return func(name string, args ...string) (string, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Stdin = nil
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
}

// fixPlatform writes the drop-in and audit rules. Root only. Files that
// already hold the expected content are left alone.
func fixPlatform(opts Options, w io.Writer) ([]Result, int) {
	var results []Result
	if os.Geteuid() != 0 {
		results = append(results, Result{Name: "fix", Status: StatusFail,
			Detail: "writing " + SSHDDropInPath + " and " + AuditRulesPath + " needs root",
			Fix:    "sudo whotyped check --fix"})
		return results, ExitNeedsRoot
	}
	code := ExitOK

	res, changed := installFile(SSHDDropInPath, SSHDDropIn, 0o644)
	results = append(results, res)
	if res.Status == StatusFail {
		code = ExitCannotRun
	}
	if changed || res.Status == StatusPass {
		// Warn when the main config does not include the drop-in directory.
		if f, err := os.Open("/etc/ssh/sshd_config"); err == nil {
			s := ParseSSHDConfig(f)
			f.Close()
			if !includesDropIns(s.Includes) {
				results = append(results, Result{Name: "fix.sshd.include", Status: StatusWarn,
					Detail: "/etc/ssh/sshd_config has no `Include /etc/ssh/sshd_config.d/*.conf`; the drop-in is inert",
					Fix:    "add that Include line at the top of /etc/ssh/sshd_config"})
				code = max(code, ExitDegraded)
			}
		}
		// Syntax-check before telling the operator to reload.
		run := opts.Exec
		if run == nil {
			run = defaultExec()
		}
		if _, stderr, err := run("sshd", "-t"); err != nil {
			results = append(results, Result{Name: "fix.sshd.syntax", Status: StatusFail,
				Detail: "`sshd -t` rejects the configuration: " + strings.TrimSpace(firstLine(stderr)),
				Fix:    "inspect " + SSHDDropInPath + "; do not reload until sshd -t passes"})
			code = ExitCannotRun
		} else {
			results = append(results, Result{Name: "fix.sshd.syntax", Status: StatusPass, Detail: "`sshd -t` accepts the configuration"})
		}
	}

	res, _ = installFile(AuditRulesPath, AuditRules, 0o640)
	results = append(results, res)
	if res.Status == StatusFail {
		code = ExitCannotRun
	}

	fmt.Fprintln(w, "Files installed. Apply them without restarting anything:")
	fmt.Fprintln(w, "  systemctl reload ssh      # Debian/Ubuntu   (or: systemctl reload sshd on RHEL/Fedora/SUSE)")
	fmt.Fprintln(w, "  augenrules --load         # loads /etc/audit/rules.d/*.rules into the running auditd")
	fmt.Fprintln(w, "  whotyped check            # confirm coverage")
	return results, code
}

func includesDropIns(includes []string) bool {
	for _, inc := range includes {
		if strings.Contains(inc, "sshd_config.d") {
			return true
		}
	}
	return false
}

// installFile writes content to path atomically unless it is already there.
func installFile(path, content string, mode os.FileMode) (Result, bool) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return Result{Name: "fix." + filepath.Base(path), Status: StatusPass, Detail: path + " already up to date"}, false
	} else if err == nil {
		// Different content: keep a copy of what was there.
		_ = os.WriteFile(path+".whotyped-bak", cur, mode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Result{Name: "fix." + filepath.Base(path), Status: StatusFail, Detail: err.Error(),
			Fix: "create " + filepath.Dir(path) + " (is the package that owns it installed?)"}, false
	}
	tmp := path + ".whotyped-tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return Result{Name: "fix." + filepath.Base(path), Status: StatusFail, Detail: err.Error()}, false
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return Result{Name: "fix." + filepath.Base(path), Status: StatusFail, Detail: err.Error()}, false
	}
	return Result{Name: "fix." + filepath.Base(path), Status: StatusPass, Detail: "wrote " + path}, true
}
