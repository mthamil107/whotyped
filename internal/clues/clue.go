// Package clues holds the detectors that turn a session Track into scored Clues.
package clues

import "time"

// Category groups clues for capping.
type Category string

const (
	CatBanner   Category = "banner"
	CatRhythm   Category = "rhythm"
	CatPTY      Category = "pty"
	CatStyle    Category = "style"
	CatProcess  Category = "process"
	CatFlags    Category = "flags"
	CatNetwork  Category = "network"
	CatIdentity Category = "identity"
)

// Clue is one piece of evidence with a weight. Negative weights are allowed
// (human indicators). Evidence must already be privacy-redacted.
type Clue struct {
	ID       string    `json:"clue"`
	Category Category  `json:"category"`
	Weight   int       `json:"weight"`
	Evidence string    `json:"evidence"`
	TS       time.Time `json:"ts,omitempty"`
}
