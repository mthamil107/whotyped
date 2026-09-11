package score

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// Config tunes the Scorer. Use DefaultConfig() and override fields; New fills
// zero-valued Thresholds/Window/CommandText/Detectors but cannot tell an
// explicit RequireTwoCategories=false from an unset one, so DefaultConfig is
// where the "true" default lives.
type Config struct {
	Thresholds           Thresholds
	RequireTwoCategories bool // alert/high need >= 2 contributing categories (spec default true)
	Window               time.Duration
	CommandText          string // privacy.command_text: redacted | full | none
	Detectors            []clues.Detector
}

// DefaultConfig returns the spec defaults.
func DefaultConfig() Config {
	return Config{
		Thresholds:           DefaultThresholds,
		RequireTwoCategories: true,
		Window:               15 * time.Minute,
		CommandText:          "redacted",
		Detectors:            clues.All(),
	}
}

// CategoryCaps bounds the contribution of each clue category (spec §5).
var CategoryCaps = map[clues.Category]int{
	clues.CatBanner:   35,
	clues.CatRhythm:   45,
	clues.CatPTY:      15,
	clues.CatStyle:    30,
	clues.CatProcess:  45,
	clues.CatFlags:    25,
	clues.CatNetwork:  30,
	clues.CatIdentity: 0,
}

// pagerGuardPrefix identifies the style clues that share one cap.
const pagerGuardPrefix = "style." + clues.GroupPagerGuard + "."

// Scorer turns a Track plus rules into a Verdict. It is stateless and safe
// for concurrent use.
type Scorer struct {
	cfg Config
}

// New returns a Scorer, applying defaults to zero-valued fields.
func New(cfg Config) *Scorer {
	if cfg.Thresholds == (Thresholds{}) {
		cfg.Thresholds = DefaultThresholds
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.CommandText == "" {
		cfg.CommandText = "redacted"
	}
	if cfg.Detectors == nil {
		cfg.Detectors = clues.All()
	}
	return &Scorer{cfg: cfg}
}

// Config returns the effective configuration.
func (s *Scorer) Config() Config { return s.cfg }

// Evaluate scores one track at instant now against the rule pack.
func (s *Scorer) Evaluate(t *session.Track, p *rules.Pack, now time.Time) Verdict {
	v := Verdict{Reasons: []clues.Clue{}, Suppressed: []Suppression{}, Mode: "unknown"}
	if t == nil {
		v.Class, v.Level = ClassHuman, LevelNone
		return v
	}
	if t.Mode != "" {
		v.Mode = t.Mode
	}

	var all []clues.Clue
	for _, d := range s.cfg.Detectors {
		all = append(all, d.Evaluate(t, p, now)...)
	}

	// Allowlist profile: zero the clues it suppresses.
	prof, _ := MatchProfile(t, p)
	if prof != nil {
		v.Profile = prof.ID
		all, v.Suppressed = applyProfile(prof, all)
	}

	// Positive weights per category with the pager_guard group cap first.
	sums := map[clues.Category]int{}
	pager := 0
	for _, c := range all {
		if c.Weight <= 0 {
			continue
		}
		if strings.HasPrefix(c.ID, pagerGuardPrefix) {
			pager += c.Weight
			continue
		}
		sums[c.Category] += c.Weight
	}
	sums[clues.CatStyle] += min(pager, clues.PagerGuardCap)
	total := 0
	for cat, sum := range sums {
		capped := sum
		if cap, ok := CategoryCaps[cat]; ok && capped > cap {
			capped = cap
		}
		if capped > 0 {
			total += capped
			v.Categories++
		}
	}

	// Negative (human) clues, then clamp.
	neg := 0
	kept := all[:0]
	for _, c := range all {
		if c.Weight < 0 {
			if c.ID == "pty.interactive" && sums[clues.CatProcess] > 0 {
				continue // an agent process under an interactive shell is still an agent
			}
			neg -= c.Weight
		}
		kept = append(kept, c)
	}
	score := max(0, min(100, total-neg))

	// Profile max_score never hides agent processes unless explicitly allowed.
	if prof != nil && prof.MaxScore > 0 && score > prof.MaxScore {
		protected := sums[clues.CatProcess] > 0 || sums[clues.CatFlags] > 0
		if !protected || prof.AllowAgentProcesses {
			score = prof.MaxScore
		}
	}
	v.Score = score

	v.Level = s.level(score)
	if s.cfg.RequireTwoCategories && v.Level.Rank() >= LevelAlert.Rank() && v.Categories < 2 {
		v.Level = LevelInfo
	}

	agentID := clues.IdentifyAgent(t, p)
	switch {
	case t.DeclaredAgent != "":
		v.Class = ClassDeclared
		v.Agent = t.DeclaredAgent
		if v.Level.Rank() < LevelInfo.Rank() {
			v.Level = LevelInfo
		}
	case v.Level.Rank() >= LevelAlert.Rank():
		v.Class = ClassSuspected
		if agentID != "" {
			v.Agent = "?" + agentID
		} else {
			v.Agent = "?generic-tool"
		}
	default:
		v.Class = ClassHuman
		if agentID != "" {
			v.Agent = "?" + agentID
		}
	}

	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Weight != kept[j].Weight {
			return kept[i].Weight > kept[j].Weight
		}
		return kept[i].ID < kept[j].ID
	})
	v.Reasons = append(v.Reasons, kept...)
	return v
}

func (s *Scorer) level(score int) Level {
	th := s.cfg.Thresholds
	switch {
	case score >= th.High:
		return LevelHigh
	case score >= th.Alert:
		return LevelAlert
	case score >= th.Info:
		return LevelInfo
	}
	return LevelNone
}

// Explain renders a verdict as one human paragraph for actions_hint.
func Explain(v Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Score %d/100 (%s, %s", v.Score, v.Level, describeClass(v))
	if v.Mode != "" && v.Mode != "unknown" {
		fmt.Fprintf(&b, ", %s", strings.ReplaceAll(v.Mode, "_", " "))
	}
	b.WriteString(").")
	var parts []string
	for _, r := range v.Reasons {
		if r.Weight == 0 && r.Category != clues.CatIdentity {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%+d): %s", r.ID, r.Weight, r.Evidence))
	}
	if len(parts) > 0 {
		b.WriteString(" Evidence: " + strings.Join(parts, "; ") + ".")
	}
	if v.Profile != "" {
		fmt.Fprintf(&b, " Allowlist profile %q matched and suppressed %d clue(s).", v.Profile, len(v.Suppressed))
	}
	b.WriteString(" " + actionHint(v))
	return b.String()
}

func describeClass(v Verdict) string {
	switch v.Class {
	case ClassDeclared:
		return "declared agent " + v.Agent
	case ClassSuspected:
		if v.Agent != "" && v.Agent != "?generic-tool" {
			return "suspected agent, looks like " + strings.TrimPrefix(v.Agent, "?")
		}
		return "suspected agent, tool not identified"
	}
	return "human"
}

func actionHint(v Verdict) string {
	switch {
	case v.Class == ClassDeclared:
		return "The session declared itself as an AI agent; confirm this tool is approved for the account and that the key is scoped accordingly."
	case v.Level == LevelHigh:
		return "Treat as an unattended AI agent on this host: confirm with the key owner, review what it changed, and consider revoking the key or process until confirmed."
	case v.Level == LevelAlert:
		return "Ask the key owner whether an AI tool is driving this key; if not, rotate the key and check recent commands."
	case v.Level == LevelInfo:
		return "Some tool-like signals; monitor and re-check if the score rises."
	}
	return "No agent indicators; no action needed."
}
