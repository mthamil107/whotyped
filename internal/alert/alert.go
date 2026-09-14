// Package alert defines the v1 alert schema and the Sink interface.
package alert

import (
	"context"
	"time"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
)

// Schema is the value of the "schema" field.
const Schema = "whotyped.alert.v1"

// Event names.
const (
	EvDetected    = "agent_detected"
	EvDeclared    = "agent_declared"
	EvHigh        = "agent_high"
	EvStillActive = "agent_still_active"
	EvEnded       = "agent_ended"
	EvFreeze      = "freeze_violation"
)

// Window describes the scoring window the alert summarises.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Execs int       `json:"execs"`
}

// Freeze describes the active freeze window, if any.
type Freeze struct {
	Name  string    `json:"name"`
	Until time.Time `json:"until"`
	// Level is the configured freeze_windows[].level for the violation
	// alert; empty means high. Additive field.
	Level score.Level `json:"level,omitempty"`
}

// Alert is one line in alerts.jsonl and one message to every sink.
type Alert struct {
	Schema         string              `json:"schema"`
	TS             time.Time           `json:"ts"`
	Host           string              `json:"host"`
	Event          string              `json:"event"`
	Class          score.Class         `json:"class"`
	Mode           string              `json:"mode"`
	User           string              `json:"user"`
	SrcIP          string              `json:"src_ip"`
	KeyFingerprint string              `json:"key_fingerprint,omitempty"`
	Agent          string              `json:"agent,omitempty"`
	Score          int                 `json:"score"`
	Level          score.Level         `json:"level"`
	Reasons        []clues.Clue        `json:"reasons"`
	Suppressed     []score.Suppression `json:"suppressed"`
	SessionID      string              `json:"session_id"`
	Connections    int                 `json:"connections"`
	Window         Window              `json:"window"`
	FreezeWindow   *Freeze             `json:"freeze_window"`
	ActionsHint    string              `json:"actions_hint"`
}

// Sink delivers alerts somewhere. Send must respect ctx and return quickly;
// the dispatcher runs each sink on its own goroutine with a bounded queue.
type Sink interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}
