package auditd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/readers"
)

// execEvent renders one complete execve group (3 records) for serial n.
func execEvent(n int) string {
	m := fmt.Sprintf("msg=audit(%d.000:%d):", 1757600000+n, n)
	return fmt.Sprintf("type=SYSCALL %s arch=c000003e syscall=59 success=yes pid=%d ppid=1 auid=1000 uid=1000 ses=7 tty=(none) comm=\"cmd\" exe=\"/usr/bin/cmd\" key=\"whotyped\"\n", m, 1000+n) +
		fmt.Sprintf("type=EXECVE %s argc=2 a0=\"cmd\" a1=\"%d\"\n", m, n) +
		fmt.Sprintf("type=PROCTITLE %s proctitle=636D6400%02X\n", m, 0x30+n%10)
}

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

// renameRetry renames, retrying briefly because on Windows the tailer may be
// holding the file for the few microseconds of a poll.
func renameRetry(t *testing.T, from, to string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := os.Rename(from, to)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rename: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func collect(t *testing.T, out <-chan event.Event, n int, timeout time.Duration) []event.Event {
	t.Helper()
	var got []event.Event
	deadline := time.After(timeout)
	for len(got) < n {
		select {
		case ev := <-out:
			got = append(got, ev)
		case <-deadline:
			t.Fatalf("timeout: got %d/%d events: %+v", len(got), n, got)
		}
	}
	return got
}

func serials(evs []event.Event) string {
	var s []string
	for _, ev := range evs {
		s = append(s, ev.Field("serial"))
	}
	return strings.Join(s, ",")
}

func TestFileTailAppendAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendFile(t, path, execEvent(1)+execEvent(2))

	tail := &FileTail{Path: path, FromStart: true, Poll: 10 * time.Millisecond}
	out := make(chan event.Event, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tail.Run(ctx, out) }()

	got := collect(t, out, 2, 3*time.Second)
	if serials(got) != "1,2" {
		t.Fatalf("initial: %s", serials(got))
	}

	// Partial last line: nothing must be emitted until the newline arrives.
	e3 := execEvent(3)
	cut := len(e3) - 20
	appendFile(t, path, e3[:cut])
	time.Sleep(60 * time.Millisecond)
	select {
	case ev := <-out:
		t.Fatalf("event from a partial line: %+v", ev)
	default:
	}
	off, _ := tail.Position()
	if want := int64(len(execEvent(1)) + len(execEvent(2)) + strings.LastIndex(e3[:cut], "\n") + 1); off != want {
		t.Errorf("offset with partial line = %d, want %d", off, want)
	}
	appendFile(t, path, e3[cut:]+execEvent(4))
	got = collect(t, out, 2, 3*time.Second)
	if serials(got) != "3,4" {
		t.Fatalf("after partial: %s (cmd=%q)", serials(got), got[0].Field("cmd"))
	}

	// Rotation: last lines land in the old file just before it is renamed to
	// .1 and a fresh (smaller) file is created; nothing may be lost.
	appendFile(t, path, execEvent(5))
	renameRetry(t, path, path+".1")
	appendFile(t, path, execEvent(6))
	got = collect(t, out, 2, 3*time.Second)
	if serials(got) != "5,6" {
		t.Fatalf("after rotation: %s", serials(got))
	}
	appendFile(t, path, execEvent(7))
	got = collect(t, out, 1, 3*time.Second)
	if serials(got) != "7" {
		t.Fatalf("after rotation append: %s", serials(got))
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case ev := <-out:
		t.Fatalf("duplicate event: %+v", ev)
	default:
	}
	off, _ = tail.Position()
	if want := int64(len(execEvent(6)) + len(execEvent(7))); off != want {
		t.Errorf("offset after rotation = %d, want %d", off, want)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on cancel")
	}
	if st := tail.Parser.Stats(); st.Events != 7 || st.Malformed != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestFileTailResumeAndSeekEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendFile(t, path, execEvent(1)+execEvent(2))
	fi, _ := os.Stat(path)
	ino := fileInode(fi)

	run := func(tail *FileTail) (<-chan event.Event, context.CancelFunc) {
		out := make(chan event.Event, 64)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { tail.Run(ctx, out) }()
		return out, cancel
	}

	// Resume at the offset after event 1 (inode matches): only 2 is replayed.
	tail := &FileTail{Path: path, Offset: int64(len(execEvent(1))), Inode: ino, Poll: 10 * time.Millisecond}
	out, cancel := run(tail)
	got := collect(t, out, 1, 3*time.Second)
	cancel()
	if serials(got) != "2" {
		t.Errorf("resume: %s", serials(got))
	}

	// Default (no offset, not FromStart): start at the end, see only new data.
	tail = &FileTail{Path: path, Poll: 10 * time.Millisecond}
	out, cancel = run(tail)
	time.Sleep(40 * time.Millisecond)
	appendFile(t, path, execEvent(3))
	got = collect(t, out, 1, 3*time.Second)
	cancel()
	if serials(got) != "3" {
		t.Errorf("seek end: %s", serials(got))
	}

	// Stale inode: the saved offset is ignored and the file read from the start.
	if runtime.GOOS == "linux" {
		tail = &FileTail{Path: path, Offset: int64(len(execEvent(1))), Inode: ino + 12345, Poll: 10 * time.Millisecond}
		out, cancel = run(tail)
		got = collect(t, out, 3, 3*time.Second)
		cancel()
		if serials(got) != "1,2,3" {
			t.Errorf("stale inode: %s", serials(got))
		}
	}

	// Missing file: Run returns the open error immediately.
	err := (&FileTail{Path: filepath.Join(dir, "nope.log")}).Run(context.Background(), make(chan event.Event))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

func TestLineBuffer(t *testing.T) {
	var lb lineBuffer
	if got := lb.push([]byte("a\r\nb")); len(got) != 1 || got[0] != "a" || string(lb.partial) != "b" {
		t.Errorf("push1: %q partial=%q", got, lb.partial)
	}
	if got := lb.push([]byte("c\nd\n")); len(got) != 2 || got[0] != "bc" || got[1] != "d" || lb.partial != nil {
		t.Errorf("push2: %q partial=%q", got, lb.partial)
	}
}

func TestSocketSourceReadsAndReconnects(t *testing.T) {
	client, server := net.Pipe()
	dials := 0
	src := &SocketSource{Path: "/run/audit/audispd_events", maxBackoff: 10 * time.Millisecond}
	src.dial = func(string) (net.Conn, error) {
		dials++
		switch dials {
		case 1:
			return client, nil
		case 2:
			return nil, errors.New("connection refused") // transient: retried
		default:
			return nil, errUnsupported // makes Run give up so the test ends
		}
	}
	out := make(chan event.Event, 16)
	done := make(chan error, 1)
	go func() { done <- src.Run(context.Background(), out) }()

	go func() {
		// Two writes splitting a line in the middle exercise the line buffer.
		data := execEvent(1)
		server.Write([]byte(data[:len(data)/2]))
		time.Sleep(20 * time.Millisecond)
		server.Write([]byte(data[len(data)/2:]))
		time.Sleep(20 * time.Millisecond)
		server.Close()
	}()
	got := collect(t, out, 1, 3*time.Second)
	if serials(got) != "1" || got[0].Field("cmd") != "cmd 1" {
		t.Errorf("socket event: %+v", got)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errUnsupported) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	if dials != 3 {
		t.Errorf("dials = %d, want 3 (connect, transient failure, give up)", dials)
	}
}

func TestSocketSourceCancel(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	src := &SocketSource{dial: func(string) (net.Conn, error) { return client, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, make(chan event.Event)) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on cancel")
	}
}

func TestSocketUnsupportedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("socket dial exists on linux")
	}
	err := (&SocketSource{Path: "/run/audit/audispd_events"}).Run(context.Background(), make(chan event.Event))
	if !errors.Is(err, readers.ErrUnsupportedPlatform) {
		t.Errorf("err = %v", err)
	}
}

func TestReaderFileSourceAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	appendFile(t, path, execEvent(1))
	r := New(Options{Source: "auto", File: path, Socket: filepath.Join(dir, "no-such-socket"), FromStart: true})
	if r.Name() != "auditd" {
		t.Errorf("name = %q", r.Name())
	}
	if r.source() != "file" {
		t.Errorf("auto without socket chose %q", r.source())
	}
	out := make(chan event.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, out) }()
	got := collect(t, out, 1, 3*time.Second)
	if serials(got) != "1" {
		t.Errorf("reader: %s", serials(got))
	}
	time.Sleep(30 * time.Millisecond)
	if off, _ := r.Position(); off != int64(len(execEvent(1))) {
		t.Errorf("position = %d", off)
	}
	if st := r.Stats(); st.Events != 1 {
		t.Errorf("stats = %+v", st)
	}
	cancel()
	<-done

	var rd readers.Reader = New(Options{})
	if rd.Name() != "auditd" {
		t.Error("Reader must satisfy readers.Reader")
	}

	// Replay over every fixture gives the expected event counts.
	counts := map[string]int{
		"execve-basic.log": 1, "execve-enriched-rhel9.log": 1, "execve-claude-skip-perms.log": 1,
		"execve-bash-lc-heredoc.log": 1, "execve-chunked-arg.log": 1, "execve-aarch64.log": 1,
		"user-start-login-end.log": 4, "mixed-session.log": 14,
	}
	for name, want := range counts {
		if got := len(replayFixture(t, name)); got != want {
			t.Errorf("%s: %d events, want %d", name, got, want)
		}
	}
}
