package clues

import (
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/session"
)

func TestPTYDetector(t *testing.T) {
	cases := []struct {
		name  string
		build func(*session.Track)
		now   time.Time
		want  map[string]int
		ev    string
	}{
		{"nothing", func(*session.Track) {}, at(10), map[string]int{}, ""},
		{"two-execs-not-enough", func(tr *session.Track) { addExecChannels(tr, 2, 0, 1) }, at(10), map[string]int{}, ""},
		{"three-execs-no-pty", func(tr *session.Track) { addExecChannels(tr, 3, 0, 1) }, at(10), map[string]int{"pty.none": 15}, "0/3 sessions allocated a PTY"},
		{"tt-exec-channels-still-no-shell", func(tr *session.Track) {
			addExecChannels(tr, 4, 0, 1)
			tr.Connections[0].PTYExecCount = 4 // ssh -tt host cmd: a terminal, not a shell
		}, at(10), map[string]int{"pty.none": 15}, "4 exec channels forced a PTY (-tt)"},
		{"execs-but-one-pty-connection", func(tr *session.Track) {
			addExecChannels(tr, 5, 0, 1)
			tr.Connections = append(tr.Connections, &session.Connection{ID: "cn_2", PTY: true, PTYOpened: at(0)})
		}, at(10), map[string]int{}, ""},
		{"short-interactive-shell", func(tr *session.Track) {
			c := tr.Connections[0]
			c.PTY, c.PTYOpened, c.ShellCount = true, at(0), 1
		}, at(120), map[string]int{}, ""},
		{"long-interactive-shell", func(tr *session.Track) {
			c := tr.Connections[0]
			c.PTY, c.PTYOpened, c.ShellCount = true, at(0), 1
		}, at(23 * 60), map[string]int{"pty.interactive": -15}, "PTY shell open 23m0s"},
		{"closed-shell-uses-closed-time", func(tr *session.Track) {
			c := tr.Connections[0]
			c.PTY, c.PTYOpened, c.Closed = true, at(0), at(60)
		}, at(60 * 60), map[string]int{}, ""},
		{"no-pty-plus-old-pty-both", func(tr *session.Track) {
			tr.Connections[0].PTY, tr.Connections[0].PTYOpened = true, at(0)
			// PTY session exists so pty.none must not fire even with many execs.
			tr.Connections = append(tr.Connections, &session.Connection{ID: "cn_2", ExecCount: 9})
		}, at(600), map[string]int{"pty.interactive": -15}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tc.build(tr)
			got := (PTY{}).Evaluate(tr, testPack(), tc.now)
			g := ids(got)
			if len(g) != len(tc.want) {
				t.Fatalf("got %v want %v", g, tc.want)
			}
			for k, w := range tc.want {
				if g[k] != w {
					t.Fatalf("clue %s = %d want %d", k, g[k], w)
				}
			}
			if tc.ev != "" && (len(got) == 0 || !strings.Contains(got[0].Evidence, tc.ev)) {
				t.Fatalf("evidence %+v lacks %q", got, tc.ev)
			}
		})
	}
}
