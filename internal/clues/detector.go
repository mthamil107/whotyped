package clues

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// Detector turns one aspect of a Track into zero or more Clues. Detectors are
// pure functions of (track, pack, now) and safe to call from any goroutine.
type Detector interface {
	ID() string
	Evaluate(t *session.Track, p *rules.Pack, now time.Time) []Clue
}

// All returns every built-in detector in evaluation order.
func All() []Detector {
	return []Detector{
		Identity{},
		Banner{},
		Rhythm{},
		PTY{},
		Style{},
		Procs{},
		NetConn{},
	}
}

// regexCache compiles each rule regex once. Rule packs are reloaded rarely and
// the set of distinct patterns is small, so an unbounded cache is fine.
var regexCache sync.Map // pattern -> *regexp.Regexp (nil on compile error)

// compile returns the compiled, case-insensitive pattern or nil if it is invalid.
// Invalid rule regexes are silently skipped here; the rules loader validates
// packs and reports them to the operator.
func compile(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if v, ok := regexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		re = nil
	}
	regexCache.Store(pattern, re)
	return re
}

// IdentifyAgent returns the rule id of the agent most directly evidenced on
// the track (process name, env var, api host or declared name), or "".
func IdentifyAgent(t *session.Track, p *rules.Pack) string {
	if t == nil {
		return ""
	}
	if t.DeclaredAgent != "" {
		if id := agentForDeclared(t.DeclaredAgent, p); id != "" {
			return id
		}
	}
	for _, ps := range t.Procs {
		if ps.Agent != "" {
			return ps.Agent
		}
	}
	if p != nil {
		for _, ps := range t.Procs {
			if a := matchProcAgent(ps, p); a != nil {
				return a.ID
			}
		}
		for _, ps := range t.Procs {
			if a, _ := matchProcEnv(ps, p); a != nil {
				return a.ID
			}
		}
		for _, n := range t.NetConns {
			if n.Agent != "" {
				return n.Agent
			}
			if h := matchHost(n, p); h != nil && h.Agent != "" {
				return h.Agent
			}
		}
	} else {
		for _, n := range t.NetConns {
			if n.Agent != "" {
				return n.Agent
			}
		}
	}
	return ""
}

// agentForDeclared maps an AI_AGENT value ("claude-code@2.0.1") to a rule id.
func agentForDeclared(v string, p *rules.Pack) string {
	name, _, _ := strings.Cut(v, "@")
	name = strings.ToLower(strings.TrimSpace(name))
	if p != nil {
		for _, a := range p.Agents {
			if a.Disabled {
				continue
			}
			if strings.EqualFold(a.ID, name) {
				return a.ID
			}
			for _, alias := range a.EnvAIAgent {
				if strings.EqualFold(alias, name) {
					return a.ID
				}
			}
		}
	}
	return name
}

// basename is filepath.Base for Unix paths regardless of the host OS.
func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// plural returns n followed by the singular or plural noun.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
