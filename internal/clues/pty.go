package clues

import (
	"fmt"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

const (
	WeightPTYNone        = 15
	WeightPTYInteractive = -15

	minExecSessionsForNoPTY = 3
	interactiveMin          = 5 * time.Minute
)

// PTY looks at terminal allocation: tools run exec channels without a PTY,
// humans sit in an interactive shell for minutes. Only shell sessions count
// as PTY sessions: `ssh -tt host cmd` allocates a terminal for a one-command
// channel, which is still not a person at a prompt, so it neither cancels
// pty.none nor starts the pty.interactive clock.
type PTY struct{}

// ID implements Detector.
func (PTY) ID() string { return "pty" }

// Evaluate implements Detector.
func (PTY) Evaluate(t *session.Track, _ *rules.Pack, now time.Time) []Clue {
	if t == nil {
		return nil
	}
	var out []Clue
	execs := t.ExecChannels()
	ptys := t.PTYSessions()
	if execs >= minExecSessionsForNoPTY && ptys == 0 {
		ev := fmt.Sprintf("0/%d sessions allocated a PTY", execs)
		if forced := ptyExecChannels(t); forced > 0 {
			ev = fmt.Sprintf("0/%d sessions opened an interactive shell; %d exec channels forced a PTY (-tt)", execs, forced)
		}
		out = append(out, Clue{ID: "pty.none", Category: CatPTY, Weight: WeightPTYNone, TS: now, Evidence: ev})
	}
	var longest time.Duration
	for _, c := range t.Connections {
		if !c.PTY || c.PTYOpened.IsZero() {
			continue
		}
		end := now
		if !c.Closed.IsZero() && c.Closed.Before(now) {
			end = c.Closed
		}
		if d := end.Sub(c.PTYOpened); d > longest {
			longest = d
		}
	}
	if longest > interactiveMin {
		out = append(out, Clue{
			ID: "pty.interactive", Category: CatPTY, Weight: WeightPTYInteractive, TS: now,
			Evidence: "PTY shell open " + longest.Truncate(time.Minute).String(),
		})
	}
	return out
}

// ptyExecChannels sums the exec channels that requested a terminal (-tt).
func ptyExecChannels(t *session.Track) int {
	n := 0
	for _, c := range t.Connections {
		n += c.PTYExecCount
	}
	return n
}
