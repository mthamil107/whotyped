package score

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mthamil107/whotyped/internal/rules"
	"github.com/mthamil107/whotyped/internal/session"
)

// expectation is testdata/dataset/<scenario>/expected.json.
type expectation struct {
	ScoreMin int    `json:"score_min"`
	ScoreMax int    `json:"score_max"`
	Class    Class  `json:"class"`
	Level    Level  `json:"level"`
	Mode     string `json:"mode"`
	Notes    string `json:"notes"`
}

// wantedScenarios is the list simulate --offline relies on; every one must exist.
var wantedScenarios = []string{
	"human-admin", "ansible", "vscode-remote", "claude-bash-over-ssh",
	"mcp-paramiko", "local-agent-skip-flags", "declared-agent",
}

func datasetDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "dataset")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dataset dir: %v", err)
	}
	return dir
}

// TestDataset replays every scenario through the real correlator and scorer
// and checks the last verdict of the busiest track against expected.json.
func TestDataset(t *testing.T) {
	dir := datasetDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		seen[e.Name()] = true
		t.Run(e.Name(), func(t *testing.T) { runScenario(t, filepath.Join(dir, e.Name())) })
	}
	for _, name := range wantedScenarios {
		if !seen[name] {
			t.Errorf("scenario %s missing from %s", name, dir)
		}
	}
}

func runScenario(t *testing.T, dir string) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := ReadEvents(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 10 {
		t.Fatalf("only %d events; scenarios should carry 10-60", len(events))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want expectation
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	// The dataset is labelled against the shipped rule pack (every profile
	// enabled, as simulate --offline assumes), not the unit-test pack: a
	// profile that only works in testpack_test.go would pass here and still
	// fail in the field.
	pack, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := session.New(session.Options{})
	verdicts := Replay(events, c, newTestScorer(), pack)
	if len(verdicts) == 0 {
		t.Fatal("replay produced no tracks")
	}
	// The scenario's subject is the track with the most activity.
	tracks := c.Tracks()
	sort.Slice(tracks, func(i, j int) bool {
		return len(tracks[i].Execs)+len(tracks[i].Procs)+len(tracks[i].Connections) > len(tracks[j].Execs)+len(tracks[j].Procs)+len(tracks[j].Connections)
	})
	subject := tracks[0]
	v := verdicts[subject.ID]
	t.Logf("%s: score=%d class=%s level=%s mode=%s agent=%q profile=%q categories=%d tracks=%d events=%d",
		filepath.Base(dir), v.Score, v.Class, v.Level, v.Mode, v.Agent, v.Profile, v.Categories, len(tracks), len(events))
	for _, r := range v.Reasons {
		t.Logf("  %-28s %+4d  %s", r.ID, r.Weight, r.Evidence)
	}
	for _, s := range v.Suppressed {
		t.Logf("  suppressed %-17s %+4d  by %s", s.Clue, s.Weight, s.Profile)
	}

	if v.Score < want.ScoreMin || v.Score > want.ScoreMax {
		t.Errorf("score %d outside [%d,%d]", v.Score, want.ScoreMin, want.ScoreMax)
	}
	if v.Class != want.Class {
		t.Errorf("class %s want %s", v.Class, want.Class)
	}
	if want.Level != "" && v.Level != want.Level {
		t.Errorf("level %s want %s", v.Level, want.Level)
	}
	if want.Mode != "" && v.Mode != want.Mode {
		t.Errorf("mode %s want %s", v.Mode, want.Mode)
	}
	// Privacy: no reason may quote a whole multi-word command from the dataset.
	for _, ev := range events {
		cmd := ev.Field("cmd")
		if len(cmd) < 40 {
			continue
		}
		for _, r := range v.Reasons {
			if containsWhole(r.Evidence, cmd) {
				t.Errorf("evidence for %s leaks full command", r.ID)
			}
		}
	}
	// Explain never panics and mentions the score.
	if s := Explain(v); s == "" {
		t.Error("empty explanation")
	}
}

func containsWhole(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestReadEventsRejectsGarbage(t *testing.T) {
	if _, err := ReadEvents(strings.NewReader("{\"kind\":\"ssh.auth_ok\"}\n\n# comment\nnot json\n")); err == nil {
		t.Fatal("expected error")
	}
	evs, err := ReadEvents(strings.NewReader("{\"ts\":\"2026-09-11T14:00:00Z\",\"kind\":\"ssh.auth_ok\",\"user\":\"a\"}\n# c\n\n{\"ts\":\"2026-09-11T14:00:01Z\",\"kind\":\"tick\"}\n"))
	if err != nil || len(evs) != 2 || evs[0].User != "a" {
		t.Fatalf("%v %v", evs, err)
	}
	if _, err := ReadEvents(strings.NewReader("{\"user\":\"a\"}\n")); err == nil {
		t.Fatal("missing kind must fail")
	}
	// Zero-timestamp events are skipped and counted, not scored "now".
	evs, skipped, err := ReadEventsSkipped(strings.NewReader("{\"kind\":\"ssh.auth_ok\",\"user\":\"a\"}\n{\"ts\":\"2026-09-11T14:00:00Z\",\"kind\":\"tick\"}\n{\"kind\":\"tick\",\"ts\":\"0001-01-01T00:00:00Z\"}\n"))
	if err != nil || len(evs) != 1 || skipped != 2 {
		t.Fatalf("zero ts: events=%d skipped=%d err=%v", len(evs), skipped, err)
	}
}
