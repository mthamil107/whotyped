// Package score turns a Track plus rules into a Verdict.
package score

import "github.com/mthamil107/whotyped/internal/clues"

// Class is the headline classification of a track.
type Class string

const (
	ClassHuman     Class = "human"
	ClassDeclared  Class = "declared_agent"
	ClassSuspected Class = "suspected_agent"
)

// Level is the severity band derived from the score.
type Level string

const (
	LevelNone  Level = "none"
	LevelInfo  Level = "info"
	LevelAlert Level = "alert"
	LevelHigh  Level = "high"
)

// Rank orders levels for comparison.
func (l Level) Rank() int {
	switch l {
	case LevelInfo:
		return 1
	case LevelAlert:
		return 2
	case LevelHigh:
		return 3
	}
	return 0
}

// ParseLevel maps a config string to a Level ("" -> none).
func ParseLevel(s string) Level {
	switch s {
	case "info":
		return LevelInfo
	case "alert":
		return LevelAlert
	case "high":
		return LevelHigh
	}
	return LevelNone
}

// Suppression records a clue an allowlist profile zeroed.
type Suppression struct {
	Profile string `json:"profile"`
	Clue    string `json:"clue"`
	Weight  int    `json:"weight"`
	Reason  string `json:"reason,omitempty"`
}

// Thresholds are the level boundaries.
type Thresholds struct {
	Info  int `yaml:"info" json:"info"`
	Alert int `yaml:"alert" json:"alert"`
	High  int `yaml:"high" json:"high"`
}

// DefaultThresholds per the design spec.
var DefaultThresholds = Thresholds{Info: 40, Alert: 70, High: 90}

// Verdict is the scorer output for one track at one instant.
type Verdict struct {
	Score      int           `json:"score"`
	Class      Class         `json:"class"`
	Level      Level         `json:"level"`
	Mode       string        `json:"mode"`            // local_agent | remote_agent | unknown
	Agent      string        `json:"agent,omitempty"` // declared name or "?<rule id>" guess
	Reasons    []clues.Clue  `json:"reasons"`
	Suppressed []Suppression `json:"suppressed"`
	Profile    string        `json:"profile,omitempty"`
	Categories int           `json:"categories"` // number of categories contributing > 0
}
