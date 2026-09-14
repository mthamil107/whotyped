package state

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/session"
)

func sampleState() State {
	now := time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)
	return State{
		Tracks: []*session.Track{{
			ID:  "tr_1",
			Key: session.TrackKey{User: "alice", Fingerprint: "SHA256:abc", SrcIP: "10.0.0.5"},
			Connections: []*session.Connection{
				{ID: "c1", User: "alice", SrcIP: "10.0.0.5", SrcPort: 51000, Opened: now, ExecCount: 3},
			},
			Execs:     []session.ExecSample{{TS: now, Argv0: "bash", Origin: "sshlog"}},
			FirstSeen: now, LastSeen: now.Add(time.Minute),
			MaxLevel: "alert", LastAlert: now, LastScore: 75,
		}},
		JournalCursor: "s=abc;i=42",
		AuditOffset:   123456,
		AuditInode:    98765,
		Dedupe:        map[string]time.Time{"declared:tr_1": now},
	}
}

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != Version || len(s.Tracks) != 0 || s.Dedupe == nil {
		t.Fatalf("empty state: %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib", "state.json") // parent must be created
	in := sampleState()
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != Version || out.SavedAt.IsZero() {
		t.Fatalf("header %+v", out)
	}
	if out.JournalCursor != in.JournalCursor || out.AuditOffset != in.AuditOffset || out.AuditInode != in.AuditInode {
		t.Fatalf("cursors %+v", out)
	}
	if len(out.Tracks) != 1 || out.Tracks[0].ID != "tr_1" || out.Tracks[0].MaxLevel != "alert" || out.Tracks[0].LastScore != 75 {
		t.Fatalf("tracks %+v", out.Tracks)
	}
	if out.Tracks[0].Connections[0].ExecCount != 3 || len(out.Tracks[0].Execs) != 1 {
		t.Fatalf("nested %+v", out.Tracks[0])
	}
	if !out.Dedupe["declared:tr_1"].Equal(in.Dedupe["declared:tr_1"]) {
		t.Fatalf("dedupe %v", out.Dedupe)
	}
	// No temp files left behind, and the file is private.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".state-") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("perm %o", st.Mode().Perm())
		}
	}
}

func TestSaveReplacesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, sampleState()); err != nil {
		t.Fatal(err)
	}
	second := State{JournalCursor: "second"}
	if err := Save(path, second); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil || out.JournalCursor != "second" || len(out.Tracks) != 0 {
		t.Fatalf("overwrite: %+v %v", out, err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"truncated.json": `{"version":1,"tracks":[{"id":"tr_1","key":{"us`,
		"garbage.json":   "not json",
		"wrongtype.json": `{"version":"one"}`,
		"array.json":     `[1,2,3]`,
	}
	for name, body := range cases {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		s, err := Load(p)
		if err == nil {
			t.Fatalf("%s: expected error, got %+v", name, s)
		}
		if len(s.Tracks) != 0 {
			t.Fatalf("%s: corrupt load returned tracks", name)
		}
	}
	// Empty file: treated as fresh, not corrupt.
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, nil, 0o600)
	if _, err := Load(empty); err != nil {
		t.Fatalf("empty file: %v", err)
	}
	// Newer format version is refused.
	newer := filepath.Join(dir, "newer.json")
	os.WriteFile(newer, []byte(`{"version":99}`), 0o600)
	if _, err := Load(newer); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Fatalf("newer version: %v", err)
	}
	// Null track entries are dropped, not returned.
	nulls := filepath.Join(dir, "nulls.json")
	os.WriteFile(nulls, []byte(`{"version":1,"tracks":[null,{"id":"x"}]}`), 0o600)
	s, err := Load(nulls)
	if err != nil || len(s.Tracks) != 1 || s.Tracks[0].ID != "x" {
		t.Fatalf("nulls: %+v %v", s, err)
	}
}

func TestSaveFailsWhenDirIsAFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "notadir")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if err := Save(filepath.Join(blocker, "state.json"), State{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunSavesPeriodicallyAndOnStop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	var calls atomic.Int32
	snapshot := func() State {
		n := calls.Add(1)
		return State{JournalCursor: "tick-" + strconv.Itoa(int(n))}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, path, 20*time.Millisecond, snapshot) }()

	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("periodic save never ran")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
	}
	final := calls.Load()
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.JournalCursor != "tick-"+strconv.Itoa(int(final)) {
		t.Fatalf("final snapshot not saved: %q (calls=%d)", s.JournalCursor, final)
	}
}
