package clues

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

const (
	WeightStyleHeredoc     = 10
	WeightStyleCompound    = 10
	WeightStyleToolWrapper = 8
	WeightStylePagerGuard  = 5
	WeightStyleAbsPaths    = 5

	// GroupPagerGuard is the shared-cap group; the scorer caps clues whose ID
	// starts with "style."+GroupPagerGuard+"." at PagerGuardCap.
	GroupPagerGuard = "pager_guard"
	PagerGuardCap   = 15

	compoundMinOps = 2
	compoundMinLen = 80
	absPathsPerCmd = 3
	absPathsMinCmd = 3
)

// Style looks for command-text habits of tool-driven shells: heredocs, long
// compound one-liners, `bash -c` wrappers, output guards and absolute paths.
type Style struct{}

// ID implements Detector.
func (Style) ID() string { return "style" }

// styleRule is a compiled style, from the pack or built in. Either re or fn
// is set; fn returns the fragment to quote and whether the command matched.
type styleRule struct {
	id      string // clue id without the "style." prefix
	weight  int
	group   string
	minCmds int // commands that must match before the clue fires
	re      *regexp.Regexp
	fn      func(cmd string) (string, bool)
}

var (
	reHeredoc  = regexp.MustCompile(`\S+\s*<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*['"]?`)
	reCdAnd    = regexp.MustCompile(`^\s*cd\s+\S+\s*&&`)
	reWrapper  = regexp.MustCompile(`^(?:\S*/)?(?:ba|z|da|k)?sh\s+-l?c\s`)
	reAbsPath  = regexp.MustCompile(`(?:^|[\s='"(])(/(?:[\w.@+-]+/)*[\w.@+-]+)`)
	rePagerSet = map[string]*regexp.Regexp{
		"no_pager":  regexp.MustCompile(`--no-pager\b`),
		"head":      regexp.MustCompile(`\|\s*head\s+(?:-n\s*)?-?\d+`),
		"tail":      regexp.MustCompile(`\|\s*tail\s+(?:-n\s*)?-?\d+`),
		"sed_range": regexp.MustCompile(`\bsed\s+-n\s+['"]?\d+,\d+p`),
		"stderr":    regexp.MustCompile(`2>&1`),
		"timeout":   regexp.MustCompile(`(?:^|[;&|]\s*)timeout\s+\d+[smh]?\s`),
	}
)

// builtinStyles mirrors rules/styles.yaml and is used when the pack has none.
func builtinStyles() []styleRule {
	rs := []styleRule{
		{id: "heredoc", weight: WeightStyleHeredoc, minCmds: 1, re: reHeredoc},
		{id: "compound", weight: WeightStyleCompound, minCmds: 1, fn: matchCompound},
		{id: "tool_wrapper", weight: WeightStyleToolWrapper, minCmds: 1, re: reWrapper},
	}
	for _, name := range []string{"no_pager", "head", "tail", "sed_range", "stderr", "timeout"} {
		rs = append(rs, styleRule{id: GroupPagerGuard + "." + name, weight: WeightStylePagerGuard, group: GroupPagerGuard, minCmds: 1, re: rePagerSet[name]})
	}
	return append(rs, absPathsRule())
}

func absPathsRule() styleRule {
	return styleRule{id: "abs_paths", weight: WeightStyleAbsPaths, minCmds: absPathsMinCmd, fn: matchAbsPaths}
}

// packStyles converts pack rules; abs_paths stays built in (it counts across
// commands) unless the pack defines its own.
func packStyles(p *rules.Pack) []styleRule {
	var rs []styleRule
	hasAbs := false
	for _, s := range p.Styles {
		if s.Disabled {
			continue
		}
		re := compile(s.Regex)
		if re == nil {
			continue
		}
		id := s.ID
		if s.Group != "" {
			id = strings.TrimPrefix(strings.TrimPrefix(id, s.Group+"_"), s.Group+".")
			id = s.Group + "." + id
		}
		if s.ID == "abs_paths" {
			hasAbs = true
		}
		rs = append(rs, styleRule{id: id, weight: s.Weight, group: s.Group, minCmds: 1, re: re})
	}
	if !hasAbs {
		rs = append(rs, absPathsRule())
	}
	return rs
}

// Evaluate implements Detector. Each style counts once per command; the clue
// weight is fixed and the evidence carries the fragment and the count.
func (Style) Evaluate(t *session.Track, p *rules.Pack, now time.Time) []Clue {
	if t == nil {
		return nil
	}
	var cmds []string
	for _, e := range t.Execs {
		if e.Cmd != "" {
			cmds = append(cmds, e.Cmd)
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	rs := builtinStyles()
	if p != nil && len(p.Styles) > 0 {
		rs = packStyles(p)
	}
	type hit struct {
		n    int
		frag string
	}
	hits := make([]hit, len(rs))
	for _, cmd := range cmds {
		for i, r := range rs {
			frag, ok := r.match(cmd)
			if !ok {
				continue
			}
			hits[i].n++
			if hits[i].frag == "" {
				hits[i].frag = Fragment(cmd, frag)
			}
		}
	}
	var out []Clue
	for i, r := range rs {
		if hits[i].n < r.minCmds || r.weight == 0 {
			continue
		}
		out = append(out, Clue{
			ID: "style." + r.id, Category: CatStyle, Weight: r.weight, TS: now,
			Evidence: fmt.Sprintf("%s (%dx)", hits[i].frag, hits[i].n),
		})
	}
	return out
}

func (r styleRule) match(cmd string) (string, bool) {
	if r.fn != nil {
		return r.fn(cmd)
	}
	m := r.re.FindString(cmd)
	return m, m != ""
}

// matchCompound: `cd X &&` or at least two chaining operators in a long line.
func matchCompound(cmd string) (string, bool) {
	if m := reCdAnd.FindString(cmd); m != "" {
		return m, true
	}
	ops := strings.Count(cmd, "&&") + strings.Count(cmd, ";") + strings.Count(cmd, "|")
	if ops >= compoundMinOps && len(cmd) > compoundMinLen {
		return fmt.Sprintf("%d operators, len %d", ops, len(cmd)), true
	}
	return "", false
}

// matchAbsPaths: at least absPathsPerCmd distinct absolute paths in one command.
func matchAbsPaths(cmd string) (string, bool) {
	seen := map[string]bool{}
	first := ""
	for _, m := range reAbsPath.FindAllStringSubmatch(cmd, -1) {
		p := m[1]
		if seen[p] {
			continue
		}
		seen[p] = true
		if first == "" {
			first = p
		}
	}
	if len(seen) < absPathsPerCmd {
		return "", false
	}
	return fmt.Sprintf("%s +%d paths", first, len(seen)-1), true
}
