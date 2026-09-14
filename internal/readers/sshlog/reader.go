package sshlog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/readers"
)

// ErrNoSource is returned by Run when neither journald nor a syslog file is
// available.
var ErrNoSource = errors.New("sshlog: no sshd log source found (no journalctl, no /var/log/auth.log or /var/log/secure)")

// defaultFiles are tried in order in file mode when Options.File is empty.
var defaultFiles = []string{"/var/log/auth.log", "/var/log/secure"}

// Options configures the sshlog reader.
type Options struct {
	Source     string // auto | journal | file
	File       string // syslog file path; default: first of /var/log/auth.log, /var/log/secure that exists
	CursorFile string // journald cursor persistence (journal mode only)
	Since      string // journalctl --since when no cursor exists (journal mode only)
	FromStart  bool   // file mode: read existing content instead of tailing from the end
	Now        func() time.Time
	Logf       func(format string, args ...any)
}

// Reader implements readers.Reader for sshd logs.
type Reader struct {
	opts Options
}

// New returns a Reader; nothing is opened until Run.
func New(opts Options) *Reader {
	if opts.Source == "" {
		opts.Source = "auto"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Reader{opts: opts}
}

// Name implements readers.Reader.
func (r *Reader) Name() string { return Source }

// Detect decides which source Run would use and why, without side effects.
// mode is "journal", "file" or "none"; reason is human-readable for `check`.
func (r *Reader) Detect() (mode string, reason string) {
	switch r.opts.Source {
	case "journal":
		if runtime.GOOS != "linux" {
			return "none", "journal source requested but this is not Linux"
		}
		return "journal", "configured"
	case "file":
		p, err := r.filePath()
		if err != nil {
			return "none", err.Error()
		}
		return "file", p
	case "auto", "":
		if ok, why := journalAvailable(); ok {
			return "journal", why
		} else if p, err := r.filePath(); err == nil {
			return "file", p + " (" + why + ")"
		} else {
			return "none", why + "; " + err.Error()
		}
	}
	return "none", fmt.Sprintf("unknown sshlog source %q (want auto|journal|file)", r.opts.Source)
}

// filePath resolves the syslog file to tail.
func (r *Reader) filePath() (string, error) {
	if r.opts.File != "" {
		if _, err := os.Stat(r.opts.File); err != nil {
			return "", err
		}
		return r.opts.File, nil
	}
	for _, p := range defaultFiles {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no sshd syslog file found (tried /var/log/auth.log, /var/log/secure)")
}

// journalAvailable is true when journalctl is on PATH and a journal exists.
func journalAvailable() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "not linux"
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return false, "journalctl not in PATH"
	}
	if _, err := os.Stat("/run/systemd/journal"); err != nil {
		return false, "/run/systemd/journal missing"
	}
	return true, "journalctl in PATH and /run/systemd/journal present"
}

// Run implements readers.Reader.
func (r *Reader) Run(ctx context.Context, out chan<- event.Event) error {
	mode, reason := r.Detect()
	if r.opts.Logf != nil {
		r.opts.Logf("sshlog: source=%s (%s)", mode, reason)
	}
	switch mode {
	case "journal":
		js := &JournalSource{Since: r.opts.Since, CursorFile: r.opts.CursorFile, Now: r.opts.Now, Logf: r.opts.Logf}
		return js.Run(ctx, out)
	case "file":
		p, err := r.filePath()
		if err != nil {
			return err
		}
		fs := &FileSource{Path: p, FromStart: r.opts.FromStart, Now: r.opts.Now, Logf: r.opts.Logf}
		return fs.Run(ctx, out)
	}
	if r.opts.Source == "journal" && runtime.GOOS != "linux" {
		return readers.ErrUnsupportedPlatform
	}
	return fmt.Errorf("%w: %s", ErrNoSource, reason)
}
