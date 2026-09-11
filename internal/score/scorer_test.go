package score

import (
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

func newTestScorer() *Scorer { return New(DefaultConfig()) }

func TestNewDefaults(t *testing.T) {
	s := New(Config{})
	c := s.Config()
	if c.Thresholds != DefaultThresholds || c.CommandText != "redacted" || len(c.Detectors) != len(clues.All()) || c.Window == 0 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if !DefaultConfig().RequireTwoCategories {
		t.Fatal("DefaultConfig must require two categories")
	}
}

func TestEmptyTrackIsHuman(t *testing.T) {
	v := newTestScorer().Evaluate(mkTrack("alice", "10.0.0.5"), testPack(), at(1))
	if v.Score != 0 || v.Class != ClassHuman || v.Level != LevelNone || v.Mode != "remote_agent" || v.Reasons == nil || v.Suppressed == nil {
		t.Fatalf("%+v", v)
	}
	if v := newTestScorer().Evaluate(nil, testPack(), at(1)); v.Class != ClassHuman || v.Mode != "unknown" {
		t.Fatalf("nil track: %+v", v)
	}
}

func TestCategoryCapsAndSum(t *testing.T) {
	// Process: agent_name 45 + agent_env 40 = 85 -> capped 45. Flags 25. Network 30. Total 100.
	tr := mkTrack("alice", "10.0.0.5")
	tr.Mode = "local_agent"
	tr.Procs = []session.ProcSample{
		{PID: 1, Comm: "claude", Flags: []string{"--dangerously-skip-permissions"}},
		{PID: 2, Comm: "bash", Env: map[string]string{"CLAUDECODE": "1"}},
	}
	tr.NetConns = []session.NetSample{{Dst: "1.1.1.1", DstPort: 443, Host: "api.anthropic.com", Attributed: true, PID: 1}}
	v := newTestScorer().Evaluate(tr, testPack(), at(1))
	if v.Score != 100 || v.Level != LevelHigh || v.Class != ClassSuspected || v.Categories != 3 || v.Agent != "?claude-code" || v.Mode != "local_agent" {
		t.Fatalf("%+v", v)
	}
	if v.Reasons[0].ID != "proc.agent_name" { // sorted by weight desc
		t.Fatalf("reasons order: %v", v.Reasons)
	}
}

func TestStyleCapAndPagerGroupCap(t *testing.T) {
	tr := mkTrack("alice", "10.0.0.5")
	// Six different pager guards would be 30 raw; group cap 15. Plus heredoc 10, compound 10, wrapper 8 = 43 -> style cap 30.
	addCmds(tr, 0, 120,
		"bash -c cd /srv && git log --no-pager | head -n 5 2>&1",
		"bash -c cat <<'EOF' | tail -n 3",
		"bash -c sed -n '1,5p' /etc/x",
		"bash -c timeout 10 ls",
	)
	s := New(Config{RequireTwoCategories: false})
	v := s.Evaluate(tr, testPack(), at(1000))
	if v.Score != 30 || v.Categories != 1 {
		t.Fatalf("style cap: %+v", v)
	}
	// Only pager guards: 6 members -> 15.
	tr2 := mkTrack("alice", "10.0.0.5")
	addCmds(tr2, 0, 120, "git log --no-pager | head -n 5 2>&1", "ls | tail -n 3", "sed -n '1,5p' /etc/x", "timeout 10 ls")
	if v := s.Evaluate(tr2, testPack(), at(1000)); v.Score != 15 {
		t.Fatalf("pager group cap: score %d reasons %v", v.Score, reasonIDs(v))
	}
}

func TestTwoCategoryRule(t *testing.T) {
	// Banner 35 + rhythm 50->45 + pty.none 15 = 95 from three categories -> high.
	tr := mkTrack("svc", "10.0.0.42")
	tr.Connections[0].Banner = "SSH-2.0-paramiko_3.4.0"
	addExecChannels(tr, 26, 0, 0.5) // burst+regular+subsecond+sustained = 50 -> cap 45
	v := newTestScorer().Evaluate(tr, noProfiles(), at(100))
	if v.Score != 95 || v.Level != LevelHigh || v.Categories != 3 || v.Class != ClassSuspected || v.Agent != "?generic-tool" {
		t.Fatalf("%+v", v)
	}
	// A single category can never alert when the rule is on: process 45 + flags 25 = 70 is two categories,
	// so use process only (agent name + env -> 45).
	tr2 := mkTrack("alice", "10.0.0.5")
	tr2.Procs = []session.ProcSample{{PID: 1, Comm: "claude", Env: map[string]string{"CLAUDECODE": "1"}}}
	s := New(Config{Thresholds: Thresholds{Info: 10, Alert: 40, High: 90}, RequireTwoCategories: true})
	if v := s.Evaluate(tr2, noProfiles(), at(1)); v.Score != 45 || v.Level != LevelInfo || v.Categories != 1 || v.Class != ClassHuman || v.Agent != "?claude-code" {
		t.Fatalf("single category downgrade: %+v", v)
	}
	s2 := New(Config{Thresholds: Thresholds{Info: 10, Alert: 40, High: 90}, RequireTwoCategories: false})
	if v := s2.Evaluate(tr2, noProfiles(), at(1)); v.Level != LevelAlert || v.Class != ClassSuspected {
		t.Fatalf("rule off: %+v", v)
	}
}

func TestNegativeCluesAndInteractiveDrop(t *testing.T) {
	tr := mkTrack("alice", "10.0.0.5")
	c := tr.Connections[0]
	c.Banner, c.PTY, c.PTYOpened = "SSH-2.0-OpenSSH_9.9p1", true, at(0)
	addCmds(tr, 100, 60, "ls -la", "git log --no-pager | head -n 20", "vim x")
	v := newTestScorer().Evaluate(tr, testPack(), at(20*60))
	// style pager 10 - banner.human 10 - pty.interactive 15 -> floor 0
	if v.Score != 0 || v.Class != ClassHuman {
		t.Fatalf("negatives: %+v", v)
	}
	ids := reasonIDs(v)
	if ids["banner.human"] != -10 || ids["pty.interactive"] != -15 {
		t.Fatalf("negative reasons missing: %v", ids)
	}
	// With an agent process the interactive negative is dropped.
	tr.Procs = []session.ProcSample{{PID: 1, Comm: "claude"}}
	v = newTestScorer().Evaluate(tr, testPack(), at(20*60))
	if _, ok := reasonIDs(v)["pty.interactive"]; ok {
		t.Fatalf("pty.interactive should be dropped when process > 0: %v", reasonIDs(v))
	}
	if v.Score != 45+10-10 {
		t.Fatalf("score %d", v.Score)
	}
}

func TestDeclaredAgentClass(t *testing.T) {
	tr := mkTrack("bob", "10.0.0.77")
	tr.DeclaredAgent = "claude-code@2.0.1"
	v := newTestScorer().Evaluate(tr, noProfiles(), at(1))
	if v.Class != ClassDeclared || v.Level != LevelInfo || v.Agent != "claude-code@2.0.1" || v.Score != 0 {
		t.Fatalf("declared, quiet: %+v", v)
	}
	if ids := reasonIDs(v); ids["env.ai_agent"] != 0 || len(v.Reasons) != 1 {
		t.Fatalf("identity clue: %+v", v.Reasons)
	}
	// Declared and loud: level follows the score, class stays declared.
	tr.Connections[0].Banner = "SSH-2.0-paramiko_3.4.0"
	addExecChannels(tr, 20, 0, 1)
	v = newTestScorer().Evaluate(tr, noProfiles(), at(100))
	if v.Class != ClassDeclared || v.Level.Rank() < LevelAlert.Rank() || v.Score < 70 || v.Agent != "claude-code@2.0.1" {
		t.Fatalf("declared, loud: %+v", v)
	}
}

func TestAgentNaming(t *testing.T) {
	tr := mkTrack("svc", "10.0.0.42")
	tr.Connections[0].Banner = "SSH-2.0-paramiko_3.4.0"
	addExecChannels(tr, 10, 0, 1)
	tr.NetConns = []session.NetSample{{Dst: "1.1.1.1", DstPort: 443, Host: "api.openai.com"}}
	v := newTestScorer().Evaluate(tr, noProfiles(), at(100))
	if v.Level.Rank() < LevelAlert.Rank() || v.Agent != "?codex" {
		t.Fatalf("%+v", v)
	}
}

func TestExplain(t *testing.T) {
	tr := mkTrack("svc", "10.0.0.42")
	tr.Connections[0].Banner = "SSH-2.0-paramiko_3.4.0"
	addExecChannels(tr, 14, 0, 0.64)
	v := newTestScorer().Evaluate(tr, noProfiles(), at(100))
	s := Explain(v)
	// banner 35 + rhythm 40 + pty.none 15 = 90 -> high
	for _, want := range []string{"Score 90/100", "high", "suspected agent", "remote agent", "banner.library (+35)", "rhythm.burst (+20)", "Treat as an unattended AI agent"} {
		if !strings.Contains(s, want) {
			t.Errorf("Explain lacks %q: %s", want, s)
		}
	}
	if strings.Contains(s, "\n") {
		t.Error("Explain must be one paragraph")
	}
	quiet := Explain(Verdict{Class: ClassHuman, Level: LevelNone})
	if !strings.Contains(quiet, "No agent indicators") {
		t.Errorf("quiet: %s", quiet)
	}
	dec := Explain(Verdict{Class: ClassDeclared, Level: LevelInfo, Agent: "claude-code", Profile: "p", Suppressed: []Suppression{{}}})
	if !strings.Contains(dec, "declared agent claude-code") || !strings.Contains(dec, `profile "p"`) {
		t.Errorf("declared: %s", dec)
	}
}

func TestCustomDetectorsAndThresholds(t *testing.T) {
	fixed := fixedDetector{clues.Clue{ID: "x.one", Category: clues.CatBanner, Weight: 50}, clues.Clue{ID: "x.two", Category: clues.CatNetwork, Weight: 50}}
	s := New(Config{Detectors: []clues.Detector{fixed}, Thresholds: Thresholds{Info: 10, Alert: 50, High: 60}})
	v := s.Evaluate(mkTrack("a", "1.1.1.1"), nil, at(1))
	// banner capped 35 + network capped 30 = 65 -> high with custom thresholds
	if v.Score != 65 || v.Level != LevelHigh || v.Categories != 2 {
		t.Fatalf("%+v", v)
	}
}

type fixedDetector []clues.Clue

func (fixedDetector) ID() string { return "fixed" }
func (f fixedDetector) Evaluate(*session.Track, *rules.Pack, time.Time) []clues.Clue {
	return []clues.Clue(f)
}
