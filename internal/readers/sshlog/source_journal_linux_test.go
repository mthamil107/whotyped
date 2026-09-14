//go:build linux

package sshlog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
)

// fakeJournalctl installs a shell script named journalctl at the front of
// PATH. Each invocation appends its argv (one per line, then a blank line) to
// argsFile, then runs body.
func fakeJournalctl(t *testing.T, body string) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"" + argsFile + "\"\necho >> \"" + argsFile + "\"\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return argsFile
}

func fixtureAbs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func collect(t *testing.T, out <-chan event.Event, n int) []event.Event {
	t.Helper()
	var evs []event.Event
	deadline := time.After(10 * time.Second)
	for len(evs) < n {
		select {
		case ev := <-out:
			evs = append(evs, ev)
		case <-deadline:
			t.Fatalf("got %d events, want %d", len(evs), n)
		}
	}
	return evs
}

func TestJournalSourceStreamsAndWritesCursor(t *testing.T) {
	argsFile := fakeJournalctl(t, "cat '"+fixtureAbs(t, "journal.jsonl")+"'\nexit 0")
	cursor := filepath.Join(t.TempDir(), "cursor")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan event.Event, 64)
	js := &JournalSource{CursorFile: cursor, Since: "-1h", Now: func() time.Time { return now }}
	done := make(chan error, 1)
	go func() { done <- js.Run(ctx, out) }()

	evs := collect(t, out, 8)
	if evs[0].Kind != event.SSHAuthOK || evs[0].PID != 1234 {
		t.Errorf("first=%+v", evs[0])
	}
	// The fake exits immediately; Run restarts it after 1s, so the same 8
	// events show up again. Wait for that second round to prove the restart.
	collect(t, out, 8)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run=%v", err)
	}

	args, _ := os.ReadFile(argsFile)
	s := string(args)
	if !strings.Contains(s, "--cursor-file="+cursor) || !strings.Contains(s, "SYSLOG_IDENTIFIER=sshd-auth") || !strings.Contains(s, "\n+\n") {
		t.Errorf("args:\n%s", s)
	}
	if !strings.Contains(s, "--since=-1h") {
		t.Errorf("first run should pass --since when no cursor exists:\n%s", s)
	}
	c, err := os.ReadFile(cursor)
	if err != nil {
		t.Fatalf("cursor file not written: %v", err)
	}
	if !strings.Contains(string(c), "i=1a0a") {
		t.Errorf("cursor=%q, want the last __CURSOR of the fixture", c)
	}
}

func TestJournalSourceAfterCursorFallback(t *testing.T) {
	// Old journalctl: reject --cursor-file the way getopt does, exit 1.
	argsFile := fakeJournalctl(t, `for a in "$@"; do case "$a" in --cursor-file=*) echo "journalctl: unrecognized option '$a'" >&2; exit 1;; esac; done
cat '`+fixtureAbs(t, "journal.jsonl")+`'
exit 0`)
	cursor := filepath.Join(t.TempDir(), "cursor")
	if err := os.WriteFile(cursor, []byte("s=old;i=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan event.Event, 64)
	js := &JournalSource{CursorFile: cursor, Since: "-1h"}
	done := make(chan error, 1)
	go func() { done <- js.Run(ctx, out) }()
	collect(t, out, 8)
	cancel()
	<-done

	args, _ := os.ReadFile(argsFile)
	s := string(args)
	if !strings.Contains(s, "--after-cursor=s=old;i=1") {
		t.Errorf("expected --after-cursor fallback with the stored cursor:\n%s", s)
	}
	if strings.Contains(s, "--since=") {
		t.Errorf("--since must not be passed when a cursor is available:\n%s", s)
	}
	c, _ := os.ReadFile(cursor)
	if !strings.Contains(string(c), "i=1a0a") {
		t.Errorf("cursor=%q, want updated cursor", c)
	}
}

func TestJournalSourceStopsChildOnCancel(t *testing.T) {
	// Long-running child that honours SIGTERM.
	fakeJournalctl(t, "trap 'kill $! 2>/dev/null; exit 0' TERM\nsleep 60 &\nwait")
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan event.Event, 1)
	js := &JournalSource{}
	done := make(chan error, 1)
	go func() { done <- js.Run(ctx, out) }()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run=%v", err)
		}
	case <-time.After(journalStopGrace + 2*time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if d := time.Since(start); d > journalStopGrace {
		t.Errorf("took %s to stop; SIGTERM should have been enough", d)
	}
}

func TestCursorFileUnsupported(t *testing.T) {
	if cursorFileUnsupported(nil, "journalctl: unrecognized option '--cursor-file=x'") {
		t.Error("nil error must not count")
	}
	if cursorFileUnsupported(errors.New("x"), "unrecognized option '--cursor-file'") {
		t.Error("non-exit error must not count")
	}
}

func TestBoundedBuffer(t *testing.T) {
	var b boundedBuffer
	for i := 0; i < 100; i++ {
		b.Write([]byte(strings.Repeat("x", 100)))
	}
	b.Write([]byte("TAIL"))
	s := b.String()
	if len(s) > 4096 || !strings.HasSuffix(s, "TAIL") {
		t.Errorf("len=%d suffix ok=%v", len(s), strings.HasSuffix(s, "TAIL"))
	}
}
