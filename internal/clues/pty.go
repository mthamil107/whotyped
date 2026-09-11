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
// humans sit in an interactive shell for minutes.
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
		out = append(out, Clue{
			ID: "pty.none", Category: CatPTY, Weight: WeightPTYNone, TS: now,
			Evidence: fmt.Sprintf("0/%d sessions allocated a PTY", execs),
		})
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
