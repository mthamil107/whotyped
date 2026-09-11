package score

import (
	"net/netip"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// DefaultMinMatchRatio is the share of commands an any_of clause must cover
// when the profile does not set min_match_ratio.
const DefaultMinMatchRatio = 0.8

// protectedCategories are never suppressed unless allow_agent_processes.
var protectedCategories = map[clues.Category]bool{
	clues.CatProcess:  true,
	clues.CatFlags:    true,
	clues.CatIdentity: true,
}

// MatchProfile returns the first enabled allowlist profile the track matches
// and the match ratio (1.0 for profiles without any_of clauses). users,
// src_cidrs and fingerprints must all match when listed; any_of is scored
// against the commands that carry text (cmd/argv0/path regexes) and the
// ratio must reach min_match_ratio. banner_regex clauses are consulted only
// when the track has no command text at all (sshd log without auditd).
func MatchProfile(t *session.Track, p *rules.Pack) (*rules.Profile, float64) {
	if t == nil || p == nil {
		return nil, 0
	}
	for i := range p.Profiles {
		prof := &p.Profiles[i]
		if prof.Disabled {
			continue
		}
		if ok, ratio := matchOne(t, prof); ok {
			return prof, ratio
		}
	}
	return nil, 0
}

func matchOne(t *session.Track, prof *rules.Profile) (bool, float64) {
	m := prof.Match
	if len(m.Users) == 0 && len(m.SrcCIDRs) == 0 && len(m.Fingerprints) == 0 && len(m.AnyOf) == 0 {
		return false, 0 // an empty match block would allowlist everyone
	}
	if len(m.Users) > 0 && !matchUser(t.Key.User, m.Users) {
		return false, 0
	}
	if len(m.SrcCIDRs) > 0 && !matchCIDR(t.Key.SrcIP, m.SrcCIDRs) {
		return false, 0
	}
	if len(m.Fingerprints) > 0 && !matchFingerprint(t, m.Fingerprints) {
		return false, 0
	}
	if len(m.AnyOf) == 0 {
		return true, 1
	}
	minRatio := m.MinMatchRatio
	if minRatio <= 0 {
		minRatio = DefaultMinMatchRatio
	}
	ratio := anyOfRatio(t, m.AnyOf)
	return ratio >= minRatio, ratio
}

func matchUser(user string, pats []string) bool {
	for _, p := range pats {
		if p == user {
			return true
		}
		if ok, err := path.Match(p, user); err == nil && ok {
			return true
		}
	}
	return false
}

func matchCIDR(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		if pfx, err := netip.ParsePrefix(c); err == nil {
			if pfx.Contains(addr) {
				return true
			}
			continue
		}
		if one, err := netip.ParseAddr(c); err == nil && one.Unmap() == addr {
			return true
		}
	}
	return false
}

func matchFingerprint(t *session.Track, fps []string) bool {
	for _, fp := range fps {
		if fp == t.Key.Fingerprint {
			return true
		}
		for _, c := range t.Connections {
			if c.Fingerprint == fp {
				return true
			}
		}
	}
	return false
}

// anyOfRatio scores the OR of clauses as the share of text-bearing commands
// matched by any cmd/argv0/path clause. Banner clauses decide only when no
// command text is available (no auditd): a paramiko banner is shared by
// Ansible and by MCP SSH servers, so once we can see the commands they, not
// the banner, say which one it is.
func anyOfRatio(t *session.Track, clauses []rules.MatchClause) float64 {
	total, matched := 0, 0
	for _, e := range t.Execs {
		if e.Cmd == "" && e.Argv0 == "" {
			continue // sshlog exec channels carry no text; they cannot vote
		}
		total++
		if execMatches(e, clauses) {
			matched++
		}
	}
	if total > 0 {
		return float64(matched) / float64(total)
	}
	for _, cl := range clauses {
		if cl.BannerRegex == "" {
			continue
		}
		re := profileRegex(cl.BannerRegex)
		for _, b := range t.Banners() {
			if re != nil && re.MatchString(b) {
				return 1
			}
		}
	}
	return 0
}

func execMatches(e session.ExecSample, clauses []rules.MatchClause) bool {
	argv0 := e.Argv0
	if argv0 == "" {
		argv0, _, _ = strings.Cut(e.Cmd, " ")
	}
	for _, cl := range clauses {
		if re := profileRegex(cl.CmdRegex); re != nil && re.MatchString(e.Cmd) {
			return true
		}
		if re := profileRegex(cl.Argv0Regex); re != nil && re.MatchString(argv0) {
			return true
		}
		if re := profileRegex(cl.PathRegex); re != nil {
			for _, p := range absPaths(e.Cmd, argv0) {
				if re.MatchString(p) {
					return true
				}
			}
		}
	}
	return false
}

var reAbsPath = regexp.MustCompile(`(?:^|[\s='"(])(/(?:[\w.@+-]+/)*[\w.@+-]+)`)

func absPaths(cmd, argv0 string) []string {
	var out []string
	if strings.HasPrefix(argv0, "/") {
		out = append(out, argv0)
	}
	for _, m := range reAbsPath.FindAllStringSubmatch(cmd, -1) {
		out = append(out, m[1])
	}
	return out
}

var profileRegexCache sync.Map // pattern -> *regexp.Regexp or nil

func profileRegex(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if v, ok := profileRegexCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	profileRegexCache.Store(pattern, re)
	return re
}

// applyProfile zeroes the clues the profile suppresses (by clue id or
// category) and returns the survivors plus the suppression records.
func applyProfile(prof *rules.Profile, all []clues.Clue) ([]clues.Clue, []Suppression) {
	if len(prof.Suppress) == 0 {
		return all, []Suppression{}
	}
	sup := map[string]bool{}
	for _, s := range prof.Suppress {
		sup[s] = true
	}
	kept := make([]clues.Clue, 0, len(all))
	out := []Suppression{}
	for _, c := range all {
		if !(sup[c.ID] || sup[string(c.Category)]) {
			kept = append(kept, c)
			continue
		}
		if protectedCategories[c.Category] && !prof.AllowAgentProcesses {
			kept = append(kept, c)
			continue
		}
		out = append(out, Suppression{Profile: prof.ID, Clue: c.ID, Weight: c.Weight, Reason: "allowlist profile " + prof.ID})
	}
	return kept, out
}
