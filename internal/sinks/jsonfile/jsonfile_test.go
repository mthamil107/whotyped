package jsonfile

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
)

func sample(i int, ts time.Time) alert.Alert {
	return alert.Alert{
		Schema: alert.Schema, TS: ts, Host: "web-03", Event: alert.EvDetected,
		Class: score.ClassSuspected, Mode: "remote_agent", User: "alice", SrcIP: "10.0.0.5",
		Score: 70 + i, Level: score.LevelAlert,
		Reasons:    []clues.Clue{{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20, Evidence: strings.Repeat("x", 200)}},
		Suppressed: []score.Suppression{}, SessionID: "tr_" + strings.Repeat("a", 12),
		ActionsHint: "Ask alice whether an AI tool is driving this key.",
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	return n
}

func TestAppendAndReadAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "alerts.jsonl") // parent dir must be created
	s, err := New(Options{Path: path, Fsync: true})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := s.Send(context.Background(), sample(i, base.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Send after Close reopens transparently.
	if err := s.Send(context.Background(), sample(3, base.Add(3*time.Hour))); err != nil {
		t.Fatal(err)
	}
	s.Close()

	all, err := ReadAll(path, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 || all[0].Score != 70 || all[3].Score != 73 {
		t.Fatalf("got %d alerts: %+v", len(all), all)
	}
	recent, err := ReadAll(path, base.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 || recent[0].Score != 72 {
		t.Fatalf("since filter: %d %+v", len(recent), recent)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o640 {
			t.Fatalf("file perm %o", st.Mode().Perm())
		}
		dst, _ := os.Stat(filepath.Dir(path))
		if dst.Mode().Perm() != 0o750 {
			t.Fatalf("dir perm %o", dst.Mode().Perm())
		}
	}
}

func TestReadAllMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	if as, err := ReadAll(path, time.Time{}); err != nil || len(as) != 0 {
		t.Fatalf("missing file: %v %v", as, err)
	}
	if as, err := ReadAll(filepath.Join(dir, "nodir", "x.jsonl"), time.Time{}); err != nil || len(as) != 0 {
		t.Fatalf("missing dir: %v %v", as, err)
	}
	s, err := New(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(context.Background(), sample(0, time.Now()))
	s.Close()
	// A torn last line (crash mid-write) and garbage must not poison the file.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	f.WriteString(`{"schema":"whotyped.alert.v1","event":"agent_de`)
	f.WriteString("\nnot json at all\n\n")
	f.Close()
	as, err := ReadAll(path, time.Time{})
	if err != nil || len(as) != 1 {
		t.Fatalf("corrupt tail: %d %v", len(as), err)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	s, err := New(Options{Path: path, MaxSizeMB: 1, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	s.maxBytes = 4000 // a handful of ~800-byte sample lines per file
	base := time.Now().UTC().Truncate(time.Second)
	const n = 20
	for i := 0; i < n; i++ {
		if err := s.Send(context.Background(), sample(i, base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	for _, want := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected %s: %v", want, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("Keep=2 but .3 exists")
	}
	total := countLines(t, path) + countLines(t, path+".1") + countLines(t, path+".2")
	if total >= n || total < 6 {
		t.Fatalf("unexpected surviving line count %d", total)
	}
	all, err := ReadAll(path, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != total {
		t.Fatalf("ReadAll %d lines, files hold %d", len(all), total)
	}
	// Oldest first across siblings, and the newest alert survived.
	for i := 1; i < len(all); i++ {
		if all[i].TS.Before(all[i-1].TS) {
			t.Fatalf("not sorted at %d", i)
		}
	}
	if all[len(all)-1].Score != 70+n-1 {
		t.Fatalf("newest alert missing, last score %d", all[len(all)-1].Score)
	}
}

func TestRotationKeepZeroTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	s, err := New(Options{Path: path, MaxSizeMB: 1, Keep: 0})
	if err != nil {
		t.Fatal(err)
	}
	s.maxBytes = 3000
	for i := 0; i < 10; i++ {
		if err := s.Send(context.Background(), sample(i, time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Fatal("Keep=0 should not create .1")
	}
	if got := countLines(t, path); got == 0 || got > 3 {
		t.Fatalf("expected a freshly truncated file, got %d lines", got)
	}
}

func TestNewRequiresPath(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error for empty path")
	}
}

// TestRefusesSymlinkAndNonRegularTargets: a planted symlink or FIFO at the
// alerts path must be refused, not written through.
func TestRefusesSymlinkAndNonRegularTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.jsonl")
	link := filepath.Join(dir, "alerts.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not permitted here: %v", err)
	}
	if _, err := New(Options{Path: link}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink accepted: %v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("open followed the symlink and created the target")
	}
	if _, err := New(Options{Path: dir}); err == nil {
		t.Fatal("directory accepted as alerts file")
	}
}
