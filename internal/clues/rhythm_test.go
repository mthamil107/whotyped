package clues

import (
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/session"
)

func TestRhythmDetector(t *testing.T) {
	cases := []struct {
		name  string
		build func(*session.Track)
		want  map[string]int
		ev    string
	}{
		{"empty", func(*session.Track) {}, map[string]int{}, ""},
		{"three-execs-too-few", func(tr *session.Track) { addExecChannels(tr, 3, 0, 1) }, map[string]int{}, ""},
		{"burst-regular-subsecond", func(tr *session.Track) { addExecChannels(tr, 14, 0, 0.64) },
			map[string]int{"rhythm.burst": 20, "rhythm.regular": 10, "rhythm.subsecond": 10}, "14 exec channels in 8.3s, median gap 640ms, cv 0.00"},
		{"burst-only-irregular", func(tr *session.Track) {
			// 8 execs within 5 minutes, but wildly irregular and slow.
			for _, s := range []float64{0, 3, 40, 41, 90, 150, 151, 280} {
				tr.Connections[0].ExecCount++
				tr.Execs = append(tr.Execs, session.ExecSample{TS: at(s), Origin: "sshlog"})
			}
		}, map[string]int{"rhythm.burst": 20, "rhythm.think_time": 15}, ""},
		{"regular-but-slow-no-burst", func(tr *session.Track) { addExecChannels(tr, 6, 0, 70) },
			map[string]int{"rhythm.regular": 10}, ""},
		{"human-pace", func(tr *session.Track) {
			for _, s := range []float64{0, 25, 90, 130, 400, 700} {
				tr.Execs = append(tr.Execs, session.ExecSample{TS: at(s), Origin: "auditd", Cmd: "ls"})
			}
		}, map[string]int{}, ""},
		{"sustained", func(tr *session.Track) { addExecChannels(tr, 25, 0, 20) },
			map[string]int{"rhythm.burst": 20, "rhythm.regular": 10, "rhythm.sustained": 10}, "25 exec channels"},
		{"subsecond-ignores-long-idle", func(tr *session.Track) {
			addExecChannels(tr, 4, 0, 0.5)
			addExecChannels(tr, 4, 600, 0.5) // 10 minutes later
		}, map[string]int{"rhythm.subsecond": 10}, ""},
		{"dedupe-sshlog-plus-auditd", func(tr *session.Track) {
			// 5 exec channels, each followed by two execve records within 200ms:
			// 15 raw samples but only 5 commands -> below the burst threshold.
			for i := 0; i < 5; i++ {
				base := float64(i) * 10
				tr.Connections[0].ExecCount++
				tr.Execs = append(tr.Execs,
					session.ExecSample{TS: at(base), Origin: "sshlog"},
					session.ExecSample{TS: at(base + 0.015), Origin: "auditd", Cmd: "bash -c ls"},
					session.ExecSample{TS: at(base + 0.030), Origin: "auditd", Cmd: "ls"})
			}
		}, map[string]int{}, ""},
		{"auditd-only-noun-commands", func(tr *session.Track) {
			for i := 0; i < 8; i++ {
				tr.Execs = append(tr.Execs, session.ExecSample{TS: at(float64(i)), Origin: "auditd", Cmd: "ls"})
			}
		}, map[string]int{"rhythm.burst": 20, "rhythm.regular": 10, "rhythm.subsecond": 10}, "8 commands in 7s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tc.build(tr)
			got := (Rhythm{}).Evaluate(tr, testPack(), at(1000))
			g := ids(got)
			if len(g) != len(tc.want) {
				t.Fatalf("got %v want %v", g, tc.want)
			}
			for k, w := range tc.want {
				if g[k] != w {
					t.Fatalf("clue %s = %d want %d", k, g[k], w)
				}
			}
			if tc.ev != "" {
				var all []string
				for _, c := range got {
					all = append(all, c.Evidence)
				}
				if s := strings.Join(all, " | "); !strings.Contains(s, tc.ev) {
					t.Fatalf("evidence %q lacks %q", s, tc.ev)
				}
			}
		})
	}
}

func TestRhythmStats(t *testing.T) {
	gaps := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 90 * time.Second}
	if m := medianGap(gaps, 60*time.Second); m != 2*time.Second {
		t.Fatalf("median %v", m)
	}
	if m := medianGap([]time.Duration{90 * time.Second}, 60*time.Second); m != 0 {
		t.Fatalf("median of only-long gaps should be 0, got %v", m)
	}
	if cv := coefficientOfVariation([]time.Duration{time.Second, time.Second, time.Second}); cv != 0 {
		t.Fatalf("cv of constant gaps = %v", cv)
	}
	if n := maxInSpan([]time.Time{at(0), at(100), at(200), at(301), at(302)}, 5*time.Minute); n != 4 {
		t.Fatalf("maxInSpan = %d", n)
	}
}

// TestThinkTime pins the pacing clue to the real pilot sessions it was
// derived from and to the shapes it must not fire on.
func TestThinkTime(t *testing.T) {
	channels := func(offsets ...float64) *session.Track {
		tr := &session.Track{Connections: []*session.Connection{{}}}
		for _, s := range offsets {
			tr.Connections[0].ExecCount++
			tr.Execs = append(tr.Execs, session.ExecSample{TS: at(s), Origin: "sshlog"})
		}
		return tr
	}
	has := func(tr *session.Track) bool {
		for _, c := range (Rhythm{}).Evaluate(tr, nil, at(1000)) {
			if c.ID == "rhythm.think_time" {
				return true
			}
		}
		return false
	}
	// Real Claude Code over SSH on the pilot host: 16 channels in 2m28s, gaps 2 to 22 s.
	pilot := channels(0, 4, 9, 11, 19, 33, 40, 48, 55, 71, 79, 92, 100, 114, 136, 148)
	if !has(pilot) {
		t.Error("real agent pacing did not fire")
	}
	if has(channels(0, 5, 10, 15, 20, 25, 30, 35, 40, 45)) {
		t.Error("a regular 5 s loop (a script) fired")
	}
	if has(channels(0, 4, 9, 11, 19, 33, 40)) {
		t.Error("7 channels fired")
	}
	if has(channels(0, 0.3, 0.5, 1.1, 1.2, 1.9, 2.0, 2.4, 3.9, 4.0)) {
		t.Error("sub-second tool bursts fired (that is rhythm.subsecond's job)")
	}
	if has(channels(0, 45, 130, 170, 260, 300, 390, 440, 520)) {
		t.Error("gaps of minutes fired")
	}
	// Commands without SSH exec channels (auditd children of one command) never count.
	tr := &session.Track{Connections: []*session.Connection{{}}}
	for _, s := range []float64{0, 4, 9, 11, 19, 33, 40, 48, 55, 71} {
		tr.Execs = append(tr.Execs, session.ExecSample{TS: at(s), Origin: "auditd", Cmd: "ls"})
	}
	if has(tr) {
		t.Error("auditd-only commands fired")
	}
}
