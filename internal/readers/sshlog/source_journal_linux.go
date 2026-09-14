//go:build linux

package sshlog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

const (
	journalBackoffMin  = time.Second
	journalBackoffMax  = 30 * time.Second
	journalHealthyRun  = time.Minute // a run this long resets the backoff
	journalCursorFlush = 5 * time.Second
	journalStopGrace   = 3 * time.Second
)

func (s *JournalSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *JournalSource) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Run keeps a journalctl child alive until ctx is done.
//
// Cursor handling: journalctl >= 242 accepts --cursor-file and writes the
// cursor itself on exit. Older versions reject the flag; that is detected
// from the exit status plus stderr and the source falls back to
// --after-cursor=<content of CursorFile>. In both modes the last __CURSOR
// seen is also written to CursorFile by us every few seconds, so a crash or
// SIGKILL of journalctl does not lose the position.
func (s *JournalSource) Run(ctx context.Context, out chan<- event.Event) error {
	backoff := journalBackoffMin
	useAfterCursor := false
	for {
		started := time.Now()
		stderr, err := s.runOnce(ctx, out, useAfterCursor)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !useAfterCursor && s.CursorFile != "" && cursorFileUnsupported(err, stderr) {
			s.logf("sshlog: journalctl lacks --cursor-file, falling back to --after-cursor")
			useAfterCursor = true
			continue
		}
		if time.Since(started) > journalHealthyRun {
			backoff = journalBackoffMin
		}
		s.logf("sshlog: journalctl exited (%v), restarting in %s", err, backoff)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		backoff *= 2
		if backoff > journalBackoffMax {
			backoff = journalBackoffMax
		}
	}
}

// cursorFileUnsupported recognises the getopt error an old journalctl prints
// for an unknown long option (exit status 1).
func cursorFileUnsupported(err error, stderr string) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		return false
	}
	if !strings.Contains(stderr, "cursor-file") {
		return false
	}
	return strings.Contains(stderr, "unrecognized option") || strings.Contains(stderr, "unknown option") || strings.Contains(stderr, "invalid option")
}

// runOnce runs journalctl until it exits or ctx is done, returning the tail
// of its stderr and the wait error.
func (s *JournalSource) runOnce(ctx context.Context, out chan<- event.Event, useAfterCursor bool) (string, error) {
	args := append([]string(nil), journalArgs...)
	haveCursor := false
	if s.CursorFile != "" {
		if useAfterCursor {
			if c := readCursor(s.CursorFile); c != "" {
				args = append(args, "--after-cursor="+c)
				haveCursor = true
			}
		} else {
			args = append(args, "--cursor-file="+s.CursorFile)
			haveCursor = readCursor(s.CursorFile) != ""
		}
	}
	if s.Since != "" && !haveCursor {
		args = append(args, "--since="+s.Since)
	}

	cmd := exec.Command("journalctl", args...)
	cmd.Stdin = nil
	// A minimal environment: the child needs PATH to find its own helpers
	// and a C locale for stable output. Nothing else of the daemon's
	// environment (sink credentials in *_ENV variables, proxies) is passed.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	// Stop journalctl gently on ctx so that --cursor-file gets written.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-stopped:
			case <-time.After(journalStopGrace):
				_ = cmd.Process.Kill()
			}
		case <-stopped:
		}
	}()

	var (
		mu         sync.Mutex
		lastCursor string
		flushed    string
	)
	flush := func() {
		mu.Lock()
		c := lastCursor
		mu.Unlock()
		if c != "" && c != flushed && s.CursorFile != "" {
			if err := writeCursor(s.CursorFile, c); err == nil {
				flushed = c
			} else {
				s.logf("sshlog: writing cursor file: %v", err)
			}
		}
	}
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		t := time.NewTicker(journalCursorFlush)
		defer t.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-t.C:
				flush()
			}
		}
	}()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var readErr error
	for sc.Scan() {
		l, ok := ParseJournalJSON(sc.Bytes())
		if !ok {
			continue
		}
		if l.Cursor != "" {
			mu.Lock()
			lastCursor = l.Cursor
			mu.Unlock()
		}
		if l.TS.IsZero() {
			l.TS = s.now()
		}
		ev, ok := ParseMessage(l)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			readErr = ctx.Err()
		}
		if readErr != nil {
			break
		}
	}
	if readErr != nil {
		// We stopped reading early; closing the pipe lets Wait return.
		_ = stdout.Close()
	}
	waitErr := cmd.Wait()
	close(stopped)
	<-flushDone
	flush()
	if readErr != nil {
		return stderr.String(), readErr
	}
	return stderr.String(), waitErr
}

func readCursor(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeCursor writes atomically (tmp + rename) in the same one-line format
// journalctl --cursor-file uses, so the two writers are interchangeable.
func writeCursor(path, cursor string) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, []byte(cursor+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// boundedBuffer keeps the last few KB written to it; enough to recognise a
// getopt error without letting a chatty child grow memory.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	if n := b.buf.Len() - 4096; n > 0 {
		b.buf.Next(n) // discard the oldest bytes
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
