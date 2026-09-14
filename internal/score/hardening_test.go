package score

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/readers/auditd"
	"github.com/whotyped/whotyped/internal/readers/sshlog"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// shippedPack is the embedded rule pack with every profile enabled, i.e. the
// pack an operator gets who lists all profiles in allowlist.profiles_enabled.
func shippedPack(t *testing.T) *rules.Pack {
	t.Helper()
	p, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func loadScenario(t *testing.T, name string) []event.Event {
	t.Helper()
	f, err := os.Open(filepath.Join(datasetDir(t), name, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs, err := ReadEvents(f)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// TestAnsibleProfileNotSatisfiedByAppendedMarker: the attacker takes the
// Claude Code scenario and appends the old fragment pattern to every command.
// Anchored clauses plus the required AnsiballZ run mean the profile does not
// match and the verdict stays at alert.
func TestAnsibleProfileNotSatisfiedByAppendedMarker(t *testing.T) {
	evs := loadScenario(t, "claude-bash-over-ssh")
	for i := range evs {
		if cmd := evs[i].Field("cmd"); cmd != "" {
			evs[i].Set("cmd", cmd+" ; : /home/x/.ansible/tmp/ansible-tmp-1.2-3-4/AnsiballZ_setup.py && sleep 0")
		}
	}
	c := session.New(session.Options{})
	verdicts := Replay(evs, c, newTestScorer(), shippedPack(t))
	subject := c.Tracks()[0]
	v := verdicts[subject.ID]
	if v.Profile != "" || v.Level.Rank() < LevelAlert.Rank() {
		t.Fatalf("suffix trick matched profile %q: score=%d level=%s", v.Profile, v.Score, v.Level)
	}
	// A whole-command forgery of the required clause alone does not carry
	// the ratio either: one AnsiballZ line among 16 real channels.
	evs = loadScenario(t, "claude-bash-over-ssh")
	evs[4].Set("cmd", "/usr/bin/python3 /home/alice/.ansible/tmp/ansible-tmp-1757599830.12-4412-100/AnsiballZ_setup.py")
	c = session.New(session.Options{})
	verdicts = Replay(evs, c, newTestScorer(), shippedPack(t))
	subject = c.Tracks()[0]
	if v := verdicts[subject.ID]; v.Profile != "" || v.Level.Rank() < LevelAlert.Rank() {
		t.Fatalf("single forged module run matched profile %q: score=%d level=%s", v.Profile, v.Score, v.Level)
	}
}

// TestRatioDenominatorCountsExecChannels: sshlog exec channels without text
// still count in the denominator, so one channel whose audit children all
// match cannot carry a session of many channels.
func TestRatioDenominatorCountsExecChannels(t *testing.T) {
	p := testPack()
	tr := mkTrack("alice", "10.0.0.5")
	addExecChannels(tr, 10, 0, 1) // ten ssh commands, no text
	addCmds(tr, 0, 0.01,          // audit children of one of them
		"/bin/sh -c 'echo ~ansible && sleep 0'",
		"/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py",
		"/bin/sh -c '/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py && sleep 0'")
	if prof, ratio := MatchProfile(tr, p); prof != nil {
		t.Fatalf("matched %s at ratio %.2f; want 3/10", prof.ID, ratio)
	}
}

// TestClaudeBashWithForcedPTYStillAlerts: `ssh -tt host cmd` on every call
// allocates a terminal per exec channel; that must not cancel pty.none.
func TestClaudeBashWithForcedPTYStillAlerts(t *testing.T) {
	evs := loadScenario(t, "claude-bash-over-ssh")
	for i := range evs {
		if evs[i].Kind == "ssh.session_start" {
			evs[i].Set("tty", "pts/7")
		}
	}
	c := session.New(session.Options{})
	verdicts := Replay(evs, c, newTestScorer(), shippedPack(t))
	subject := c.Tracks()[0]
	v := verdicts[subject.ID]
	ids := reasonIDs(v)
	if _, ok := ids["pty.none"]; !ok || v.Level.Rank() < LevelAlert.Rank() {
		t.Fatalf("-tt variant: score=%d level=%s reasons=%v", v.Score, v.Level, ids)
	}
	if ptys := subject.PTYSessions(); ptys != 0 {
		t.Fatalf("PTYSessions=%d for exec channels", ptys)
	}
	for _, r := range v.Reasons {
		if r.ID == "pty.none" && !strings.Contains(r.Evidence, "forced a PTY (-tt)") {
			t.Fatalf("evidence lacks -tt note: %s", r.Evidence)
		}
	}
}

const sshlogFixtures = "../../testdata/sshlog"

// TestVerboseFixtureIsOneTrackOneConnection replays the real OpenSSH 9.6
// VERBOSE log (14 exec channels over one pooled connection, each followed by
// "Close session") through parser, correlator and scorer. Channel closes must
// not split the connection; the fingerprint must survive to the verdict.
func TestVerboseFixtureIsOneTrackOneConnection(t *testing.T) {
	f, err := os.Open(filepath.Join(sshlogFixtures, "openssh-9.6-ubuntu2404-verbose.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs := sshlog.ReplayReader(f, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	c := session.New(session.Options{})
	verdicts := Replay(evs, c, newTestScorer(), shippedPack(t))
	tracks := c.Tracks()
	if len(tracks) != 1 {
		for _, tr := range tracks {
			t.Logf("track %s", tr)
		}
		t.Fatalf("%d tracks, want 1", len(tracks))
	}
	tr := tracks[0]
	if len(tr.Connections) != 1 || tr.ExecChannels() != 14 || len(tr.Execs) != 14 {
		t.Fatalf("conns=%d channels=%d execs=%d", len(tr.Connections), tr.ExecChannels(), len(tr.Execs))
	}
	if tr.Key.Fingerprint != "SHA256:Qm3kR9pL2vX7wA1sD4fG6hJ8kL0zX2cV4bN6mQ8wE0r" || tr.Connections[0].Fingerprint != tr.Key.Fingerprint {
		t.Fatalf("fingerprint lost: key=%s conn=%s", tr.Key.Fingerprint, tr.Connections[0].Fingerprint)
	}
	if tr.Connections[0].Closed.IsZero() {
		t.Fatal("connection not closed by Disconnected line")
	}
	v := verdicts[tr.ID]
	ids := reasonIDs(v)
	// sshd lines alone give rhythm (burst+regular+subsecond = 40) and
	// pty.none (15): 55, info. Alert needs auditd style clues on top; the
	// spec caps a log-only session at 60 by design.
	if v.Score < 50 || v.Level.Rank() < LevelInfo.Rank() || ids["pty.none"] != 15 || ids["rhythm.burst"] != 20 {
		t.Fatalf("verdict score=%d level=%s reasons=%v", v.Score, v.Level, ids)
	}
	t.Logf("verbose fixture: score=%d level=%s reasons=%v", v.Score, v.Level, ids)
}

// TestAllFixturesReplayWithoutPanic pushes every sshd and auditd fixture
// through the full pipeline and checks the track counts are plausible: no
// fixture is a brute force that should mint tracks, and none is empty.
func TestAllFixturesReplayWithoutPanic(t *testing.T) {
	pack := shippedPack(t)
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	wantTracks := map[string]int{
		"openssh-8.9-ubuntu2204.log":         1,
		"openssh-9.6-ubuntu2404-verbose.log": 1,
		"openssh-9.8-sshd-session.log":       1,
		"openssh-10.0-sshd-auth.log":         1,
		"debug1-banner.log":                  2,
		"rhel9-secure.log":                   2,
		"journal.jsonl":                      1,
	}
	files, _ := filepath.Glob(filepath.Join(sshlogFixtures, "*"))
	if len(files) < 7 {
		t.Fatalf("only %d sshlog fixtures", len(files))
	}
	for _, path := range files {
		name := filepath.Base(path)
		t.Run("sshlog/"+name, func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			evs := sshlog.ReplayReader(f, now)
			if len(evs) == 0 {
				t.Fatal("fixture produced no events")
			}
			c := session.New(session.Options{})
			verdicts := Replay(evs, c, newTestScorer(), pack)
			got := len(c.Tracks())
			if want, ok := wantTracks[name]; ok && got != want {
				for _, tr := range c.Tracks() {
					t.Logf("track %s", tr)
				}
				t.Fatalf("%d tracks, want %d", got, want)
			}
			if got == 0 || got > 4 {
				t.Fatalf("implausible track count %d", got)
			}
			for id, v := range verdicts {
				if Explain(v) == "" {
					t.Errorf("empty explanation for %s", id)
				}
			}
			c.Expire(now.Add(24 * time.Hour))
			if n := len(c.Tracks()); n != 0 {
				t.Fatalf("%d tracks survived expiry", n)
			}
		})
	}
	audits, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "auditd", "*.log"))
	if len(audits) < 5 {
		t.Fatalf("only %d auditd fixtures", len(audits))
	}
	for _, path := range audits {
		t.Run("auditd/"+filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			evs := auditd.Replay(f)
			c := session.New(session.Options{})
			Replay(evs, c, newTestScorer(), pack)
			if n := len(c.Tracks()); n > 4 {
				t.Fatalf("implausible track count %d", n)
			}
		})
	}
}
