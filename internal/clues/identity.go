package clues

import (
	"time"

	"github.com/mthamil107/whotyped/internal/rules"
	"github.com/mthamil107/whotyped/internal/session"
)

// Identity reports a declared agent (AI_AGENT in the session environment or
// an accepted SetEnv). It carries no weight: declaration changes the class of
// the verdict, not the suspicion score.
type Identity struct{}

// ID implements Detector.
func (Identity) ID() string { return "identity" }

// Evaluate implements Detector.
func (Identity) Evaluate(t *session.Track, _ *rules.Pack, now time.Time) []Clue {
	if t == nil || t.DeclaredAgent == "" {
		return nil
	}
	return []Clue{{
		ID:       "env.ai_agent",
		Category: CatIdentity,
		Weight:   0,
		Evidence: "AI_AGENT=" + Fragment("", t.DeclaredAgent),
		TS:       now,
	}}
}
