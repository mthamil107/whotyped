package score

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// Replay feeds events through the correlator in order, scoring the affected
// track after each one with the event's own timestamp as "now", and returns
// the last verdict per track id. cmd (run --replay, simulate --offline) and
// the dataset tests share this path so they cannot drift apart.
func Replay(events []event.Event, c *session.Correlator, s *Scorer, p *rules.Pack) map[string]Verdict {
	out := map[string]Verdict{}
	for _, ev := range events {
		t, _ := c.Apply(ev)
		if t == nil {
			continue
		}
		out[t.ID] = s.Evaluate(t, p, ev.TS)
	}
	return out
}

// ReadEvents parses JSONL (one event.Event per line; blank lines and lines
// starting with # are skipped). Lines are decoded as JSON only; nothing in a
// field is ever re-parsed as a log line.
func ReadEvents(r io.Reader) ([]event.Event, error) {
	var out []event.Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return out, fmt.Errorf("events line %d: %w", line, err)
		}
		if ev.Kind == "" {
			return out, fmt.Errorf("events line %d: missing kind", line)
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}
