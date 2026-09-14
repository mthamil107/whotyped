package sshlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/readers"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func waitEvent(t *testing.T, ch <-chan event.Event, want event.Kind) event.Event {
	t.Helper()
	select {
	case ev := <-ch:
		if ev.Kind != want {
			t.Fatalf("got %s (%+v), want %s", ev.Kind, ev, want)
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", want)
	}
	return event.Event{}
}

func expectQuiet(t *testing.T, ch <-chan event.Event, d time.Duration) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(d):
	}
}

func TestFileSourceTailAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendFile(t, path, "Sep 11 14:00:00 web-03 sshd[1]: Accepted password for old from 1.1.1.1 port 1 ssh2\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan event.Event, 64)
	src := &FileSource{Path: path, Poll: 50 * time.Millisecond, Now: func() time.Time { return now }}
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	// Existing content is skipped when FromStart is false.
	expectQuiet(t, out, 200*time.Millisecond)

	// Appended line arrives.
	appendFile(t, path, "Sep 11 14:03:22 web-03 sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:x\n")
	ev := waitEvent(t, out, event.SSHAuthOK)
	if ev.User != "alice" || ev.PID != 1234 {
		t.Errorf("ev=%+v", ev)
	}

	// A partial line is held until its newline arrives.
	appendFile(t, path, "Sep 11 14:03:23 web-03 sshd[1240]: Starting session: shell on pts/0 for alice")
	expectQuiet(t, out, 200*time.Millisecond)
	appendFile(t, path, " from 203.0.113.5 port 51234 id 0\n")
	ev = waitEvent(t, out, event.SSHSessionStart)
	if ev.Field("tty") != "pts/0" {
		t.Errorf("ev=%+v", ev)
	}

	// copytruncate rotation: same file, shrinks to zero.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // let a poll observe the shrink
	appendFile(t, path, "Sep 11 14:05:00 web-03 sshd[1300]: Invalid user admin from 198.51.100.9 port 40000\n")
	ev = waitEvent(t, out, event.SSHAuthFail)
	if ev.User != "admin" {
		t.Errorf("ev=%+v", ev)
	}

	// rename rotation: old file moved away, new file created at the path.
	// The remaining lines of the old file must still be delivered.
	appendFile(t, path, "Sep 11 14:06:00 web-03 sshd[1300]: Connection closed by invalid user admin 198.51.100.9 port 40000 [preauth]\n")
	if err := os.Rename(path, path+".1"); err != nil {
		if runtime.GOOS == "windows" {
			t.Logf("rename of open file not permitted here (%v); skipping rename rotation", err)
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v", err)
			}
			return
		}
		t.Fatal(err)
	}
	appendFile(t, path, "Sep 11 14:07:00 web-03 sshd[1400]: Accepted password for bob from 10.0.0.2 port 2222 ssh2\n")
	ev = waitEvent(t, out, event.SSHAuthFail)
	if ev.Field("reason") != "closed_invalid" {
		t.Errorf("ev=%+v", ev)
	}
	ev = waitEvent(t, out, event.SSHAuthOK)
	if ev.User != "bob" {
		t.Errorf("ev=%+v", ev)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v", err)
	}
}

func TestFileSourceFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendFile(t, path,
		"Sep 11 14:03:22 web-03 sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:x\n"+
			"Sep 11 14:03:22 web-03 sshd[1234]: User child is on pid 1240\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan event.Event, 8)
	src := &FileSource{Path: path, FromStart: true, Poll: 50 * time.Millisecond, Now: func() time.Time { return now }}
	go func() { _ = src.Run(ctx, out) }()
	waitEvent(t, out, event.SSHAuthOK)
	ev := waitEvent(t, out, event.SSHPAMOpen)
	if ev.Field("note") != "user_child" || ev.Field("child_pid") != "1240" {
		t.Errorf("ev=%+v", ev)
	}
}

func TestFileSourceMissing(t *testing.T) {
	src := &FileSource{Path: filepath.Join(t.TempDir(), "nope.log")}
	if err := src.Run(context.Background(), make(chan event.Event)); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReaderDetectAndRun(t *testing.T) {
	fixture := filepath.Join(fixtureDir, "openssh-8.9-ubuntu2204.log")

	r := New(Options{Source: "file", File: fixture, FromStart: true, Now: func() time.Time { return now }})
	if r.Name() != "sshlog" {
		t.Errorf("Name=%q", r.Name())
	}
	if mode, _ := r.Detect(); mode != "file" {
		t.Errorf("mode=%q", mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan event.Event, 64)
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, out) }()
	waitEvent(t, out, event.SSHAuthOK)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v", err)
	}

	r = New(Options{Source: "file", File: filepath.Join(t.TempDir(), "missing")})
	if mode, _ := r.Detect(); mode != "none" {
		t.Errorf("mode=%q want none", mode)
	}
	if err := r.Run(context.Background(), out); err == nil {
		t.Error("expected error")
	}

	r = New(Options{Source: "bogus"})
	if mode, _ := r.Detect(); mode != "none" {
		t.Errorf("mode=%q want none", mode)
	}

	if runtime.GOOS != "linux" {
		r = New(Options{Source: "journal"})
		if mode, _ := r.Detect(); mode != "none" {
			t.Errorf("mode=%q want none", mode)
		}
		if err := r.Run(context.Background(), out); !errors.Is(err, readers.ErrUnsupportedPlatform) {
			t.Errorf("Run=%v want ErrUnsupportedPlatform", err)
		}
		js := &JournalSource{}
		if err := js.Run(context.Background(), out); !errors.Is(err, readers.ErrUnsupportedPlatform) {
			t.Errorf("JournalSource.Run=%v", err)
		}
	}
}
