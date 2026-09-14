package alert

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/score"
	"github.com/whotyped/whotyped/internal/session"
)

// TestDeclaredButLoudReachesAlert: a declaration labels the track, it does
// not silence it. Once the behaviour reaches alert the threshold branch runs
// with class declared_agent, and the track ends loudly.
func TestDeclaredButLoudReachesAlert(t *testing.T) {
	c := newClock()
	sink := &fakeSink{name: "fake"}
	d := newTestDispatcher(c, sink)
	tr := newTrack()
	tr.DeclaredAgent = "claude-code"
	quiet := score.Verdict{Score: 12, Class: score.ClassDeclared, Level: score.LevelInfo, Agent: "claude-code", Mode: "remote_agent"}
	if got := flat(d.Observe(tr, quiet, nil)); len(got) != 1 || got[0] != "agent_declared/info" {
		t.Fatalf("quiet declared: %v", got)
	}
	loud := quiet
	loud.Score, loud.Level = 75, score.LevelAlert
	got := d.Observe(tr, loud, nil)
	if len(got) != 1 || got[0].Event != EvDetected || got[0].Level != score.LevelAlert || got[0].Class != score.ClassDeclared || got[0].Agent != "claude-code" {
		t.Fatalf("loud declared: %v %+v", flat(got), got)
	}
	if !strings.Contains(got[0].ActionsHint, "Declared agent claude-code shows strong agent behaviour") {
		t.Fatalf("hint %q", got[0].ActionsHint)
	}
	// Repeat within the interval is quiet; high is a new crossing.
	c.advance(time.Minute)
	if again := d.Observe(tr, loud, nil); len(again) != 0 {
		t.Fatalf("repeated: %v", flat(again))
	}
	loud.Score, loud.Level = 95, score.LevelHigh
	if again := flat(d.Observe(tr, loud, nil)); len(again) != 1 || again[0] != "agent_high/high" {
		t.Fatalf("high crossing: %v", again)
	}
	a := d.Ended(tr)
	if a == nil || a.Class != score.ClassDeclared || a.Level != score.LevelHigh {
		t.Fatalf("ended: %+v", a)
	}
	// A track that is declared and loud from its first evaluation emits both
	// in one Observe call.
	tr2 := newTrack()
	tr2.ID = "tr_test0002"
	tr2.DeclaredAgent = "claude-code"
	if got := flat(d.Observe(tr2, loud, nil)); strings.Join(got, " ") != "agent_declared/info agent_high/high" {
		t.Fatalf("first-eval loud declared: %v", got)
	}
	d.Close()
	if ev := strings.Join(sink.events(), " "); !strings.Contains(ev, "agent_detected/alert") || !strings.Contains(ev, "agent_ended/high") {
		t.Fatalf("sink saw %s", ev)
	}
}

// TestFreezeUsesScorerVerdicts drives the freeze branch with verdicts the
// real scorer produces: 40-69 is class human at level info, and inside a
// freeze that is a violation; a quiet human is not. The configured freeze
// level is carried on the alert.
func TestFreezeUsesScorerVerdicts(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	sc := score.New(score.DefaultConfig())
	pack, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := c.t
	mid := &session.Track{ID: "tr_mid", Key: session.TrackKey{User: "alice", Fingerprint: "SHA256:abc", SrcIP: "10.0.0.5"},
		Connections: []*session.Connection{{ID: "c1", User: "alice", SrcIP: "10.0.0.5", SrcPort: 51000, Fingerprint: "SHA256:abc", Opened: now}},
		FirstSeen:   now, LastSeen: now, Mode: "remote_agent"}
	for i := 0; i < 8; i++ { // rhythm 40 + pty.none 15 = 55: info, human
		mid.Connections[0].ExecCount++
		mid.Execs = append(mid.Execs, session.ExecSample{TS: now.Add(time.Duration(i) * time.Second), PID: 1, Origin: "sshlog"})
	}
	v := sc.Evaluate(mid, pack, now.Add(10*time.Second))
	if v.Class != score.ClassHuman || v.Level != score.LevelInfo || v.Score < 40 || v.Score >= 70 {
		t.Fatalf("scorer verdict %+v", v)
	}
	fz := &Freeze{Name: "release", Until: now.Add(4 * time.Hour), Level: score.LevelAlert}
	got := d.Observe(mid, v, fz)
	if len(got) != 1 || got[0].Event != EvFreeze || got[0].Level != score.LevelAlert || got[0].FreezeWindow == nil || got[0].FreezeWindow.Level != score.LevelAlert {
		t.Fatalf("40-69 human in freeze: %v %+v", flat(got), got)
	}
	// Default (unset) level is high.
	quietHuman := sc.Evaluate(newTrack(), pack, now)
	if quietHuman.Level != score.LevelNone {
		t.Fatalf("quiet human %+v", quietHuman)
	}
	if got := d.Observe(newTrack(), quietHuman, &Freeze{Name: "release", Until: now.Add(time.Hour)}); len(got) != 0 {
		t.Fatalf("quiet human violated: %v", flat(got))
	}
	loud := newTrack()
	loud.ID = "tr_loud"
	if got := flat(d.Observe(loud, suspected(75), &Freeze{Name: "release", Until: now.Add(time.Hour)})); len(got) != 1 || got[0] != "freeze_violation/high" {
		t.Fatalf("default level: %v", got)
	}
}

func TestForgetReleasesMemo(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	tr := newTrack()
	tr.DeclaredAgent = "bot"
	d.Observe(tr, score.Verdict{Class: score.ClassDeclared, Level: score.LevelInfo, Agent: "bot"}, nil)
	if _, ok := d.Dedupe()["declared:"+tr.ID]; !ok {
		t.Fatal("memo missing")
	}
	d.Forget(tr.ID)
	if len(d.Dedupe()) != 0 {
		t.Fatalf("memo survived Forget: %v", d.Dedupe())
	}
}

// TestEndToEndDeclaredWithEvidence is the cross-package check: the
// declared-agent dataset scenario (AI_AGENT in the shell env plus 6 exec
// channels of tool-shaped commands, score 75) goes correlator -> scorer ->
// dispatcher and an alert-level event must reach a sink registered at
// min_level alert, i.e. the Slack/email tier.
func TestEndToEndDeclaredWithEvidence(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "testdata", "dataset", "declared-agent", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := score.ReadEvents(f)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	clk := func() time.Time { return now }
	d := New(Options{Host: "h", Now: clk, RetryBackoff: []time.Duration{}})
	info := &fakeSink{name: "jsonfile"}
	alertTier := &fakeSink{name: "slack"}
	d.Register(info, score.LevelInfo, 16)
	d.Register(alertTier, score.LevelAlert, 16)
	d.Start(context.Background())

	corr := session.New(session.Options{Now: clk})
	sc := score.New(score.DefaultConfig())
	var last score.Verdict
	for _, ev := range events {
		now = ev.TS
		tr, _ := corr.Apply(ev)
		if tr == nil {
			continue
		}
		last = sc.Evaluate(tr, pack, now)
		d.Observe(tr, last, nil)
	}
	d.Close()
	if last.Class != score.ClassDeclared || last.Level.Rank() < score.LevelAlert.Rank() {
		t.Fatalf("final verdict %+v", last)
	}
	got := strings.Join(alertTier.events(), " ")
	if !strings.Contains(got, "agent_detected/alert") {
		t.Fatalf("alert tier saw %q; info tier %q", got, strings.Join(info.events(), " "))
	}
	if all := strings.Join(info.events(), " "); !strings.Contains(all, "agent_declared/info") || !strings.Contains(all, "agent_detected/alert") {
		t.Fatalf("info tier saw %q", all)
	}
	for _, a := range alertTier.got {
		if a.Class != score.ClassDeclared || a.Agent != "claude-code@2.0.1" {
			t.Fatalf("alert lost its declaration: %+v", a)
		}
	}
}
