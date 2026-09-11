package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	defaults "github.com/whotyped/whotyped/rules"
)

// File is one YAML rule or allowlist document. A file may carry any subset
// of the sections; the schema only says which vocabulary it uses.
type File struct {
	Schema   string    `yaml:"schema"`
	Version  string    `yaml:"version,omitempty"`
	Agents   []Agent   `yaml:"agents,omitempty"`
	Banners  []Banner  `yaml:"banners,omitempty"`
	Styles   []Style   `yaml:"styles,omitempty"`
	APIHosts []Host    `yaml:"api_hosts,omitempty"`
	Profiles []Profile `yaml:"profiles,omitempty"`

	// Source is where the file came from, for error messages.
	Source string `yaml:"-"`
}

// ParseFile decodes one YAML document. Unknown keys are errors so that a
// typo in an override (`proces_names:`) is reported instead of ignored.
func ParseFile(source string, data []byte) (*File, error) {
	f := &File{Source: source}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file", source)
		}
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	switch f.Schema {
	case SchemaRules, SchemaAllowlist:
	case "":
		return nil, fmt.Errorf("%s: missing schema (want %s or %s)", source, SchemaRules, SchemaAllowlist)
	default:
		return nil, fmt.Errorf("%s: unsupported schema %q", source, f.Schema)
	}
	return f, nil
}

// Load returns the embedded default pack with every *.yaml / *.yml file of
// each extra directory merged on top, in directory order and then by file
// name. Later entries replace earlier ones with the same id; an entry with
// `disabled: true` removes the id. Directories that do not exist are
// skipped so that the default /etc/whotyped/rules.d need not be created.
func Load(extraDirs ...string) (*Pack, error) {
	p := &Pack{}
	if err := mergeFS(p, defaults.FS, "embedded"); err != nil {
		return nil, err
	}
	if err := mergeDirs(p, extraDirs); err != nil {
		return nil, err
	}
	normalize(p)
	return p, nil
}

// LoadDirs loads only the given directories, without the embedded defaults.
// `whotyped rules validate <dir>` uses it to lint an override on its own.
func LoadDirs(dirs ...string) (*Pack, error) {
	p := &Pack{}
	if err := mergeDirs(p, dirs); err != nil {
		return nil, err
	}
	normalize(p)
	return p, nil
}

func mergeDirs(p *Pack, dirs []string) error {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		st, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("rules dir %s: %w", dir, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("rules dir %s: not a directory", dir)
		}
		if err := mergeFS(p, os.DirFS(dir), dir); err != nil {
			return err
		}
	}
	return nil
}

// mergeFS parses every YAML file at the root of fsys (sorted by name) and
// merges it into p. label prefixes error messages with the origin.
func mergeFS(p *Pack, fsys fs.FS, label string) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", label, name, err)
		}
		f, err := ParseFile(label+"/"+name, data)
		if err != nil {
			return err
		}
		Merge(p, f)
	}
	return nil
}

// Merge applies one file to a pack: replace by id, remove when disabled.
// A non-empty version in a later file becomes the pack version.
func Merge(p *Pack, f *File) {
	if f.Version != "" {
		p.Version = f.Version
	}
	for _, a := range f.Agents {
		p.Agents = upsert(p.Agents, a, func(x Agent) string { return x.ID }, a.Disabled)
	}
	for _, b := range f.Banners {
		p.Banners = upsert(p.Banners, b, func(x Banner) string { return x.ID }, b.Disabled)
	}
	for _, s := range f.Styles {
		p.Styles = upsert(p.Styles, s, func(x Style) string { return x.ID }, s.Disabled)
	}
	for _, h := range f.APIHosts {
		p.APIHosts = upsert(p.APIHosts, h, hostKey, h.Disabled)
	}
	for _, pr := range f.Profiles {
		p.Profiles = upsert(p.Profiles, pr, func(x Profile) string { return x.ID }, pr.Disabled)
	}
}

// upsert replaces the element with the same key in place (keeping first-seen
// order), appends when new, or deletes it when remove is set.
func upsert[T any](list []T, item T, key func(T) string, remove bool) []T {
	k := key(item)
	for i := range list {
		if key(list[i]) != k {
			continue
		}
		if remove {
			return append(list[:i:i], list[i+1:]...)
		}
		list[i] = item
		return list
	}
	if remove {
		return list
	}
	return append(list, item)
}

// hostKey identifies an API host entry: name or CIDR plus effective port.
func hostKey(h Host) string {
	port := h.Port
	if port == 0 {
		port = 443
	}
	name := strings.ToLower(strings.TrimSpace(h.Host))
	if name == "" {
		name = strings.TrimSpace(h.CIDR)
	}
	return name + ":" + strconv.Itoa(port)
}

// normalize lower-cases the fields that are compared case-insensitively.
func normalize(p *Pack) {
	for i := range p.APIHosts {
		p.APIHosts[i].Host = strings.ToLower(strings.TrimSpace(p.APIHosts[i].Host))
	}
	for i := range p.Agents {
		for j, h := range p.Agents[i].APIHosts {
			p.Agents[i].APIHosts[j] = strings.ToLower(strings.TrimSpace(h))
		}
	}
}

// ---------------------------------------------------------------------------
// Validation

// Categories are the clue categories a profile may suppress wholesale.
var Categories = []string{"banner", "rhythm", "pty", "style", "process", "flags", "network", "identity"}

// KnownClues are the clue ids from the scoring spec (ARCHITECTURE.md section
// 5) that do not come from the styles pack. Style ids are taken from the pack.
var KnownClues = []string{
	"banner.library", "banner.automation", "banner.human",
	"rhythm.burst", "rhythm.regular", "rhythm.subsecond", "rhythm.sustained",
	"pty.none", "pty.interactive",
	"style.pager_guard",
	"proc.agent_name", "proc.agent_env", "proc.skip_flags",
	"net.ai_api", "net.ai_api_unattributed",
	"env.ai_agent",
}

// protectedSuppress lists what a profile may only suppress with
// allow_agent_processes: true (design section 6).
var protectedSuppress = map[string]bool{
	"process": true, "flags": true, "identity": true,
	"proc.agent_name": true, "proc.agent_env": true, "proc.skip_flags": true,
	"env.ai_agent": true,
}

var bannerKinds = map[string]bool{"library": true, "automation": true, "human": true}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.\-]*$`)

// Validate reports every problem it can find rather than stopping at the
// first, so an operator fixes an override file in one pass.
func Validate(p *Pack) []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	agentIDs := map[string]bool{}
	aiValues := map[string]string{}
	for _, a := range p.Agents {
		if !idRe.MatchString(a.ID) {
			add("agent %q: id must match %s", a.ID, idRe)
		}
		if agentIDs[a.ID] {
			add("agent %q: duplicate id", a.ID)
		}
		agentIDs[a.ID] = true
		if a.Display == "" {
			add("agent %q: display is required", a.ID)
		}
		for _, re := range a.SSHBanners {
			if _, err := Regex(re); err != nil {
				add("agent %q: ssh_banners %q: %v", a.ID, re, err)
			}
		}
		for _, v := range a.EnvAIAgent {
			k := strings.ToLower(v)
			if prev, dup := aiValues[k]; dup && prev != a.ID {
				add("agent %q: env_ai_agent value %q already claimed by %q", a.ID, v, prev)
			}
			aiValues[k] = a.ID
		}
		for _, h := range a.APIHosts {
			if h != strings.ToLower(h) || strings.ContainsAny(h, "/ ") {
				add("agent %q: api_hosts %q must be a lowercase host name", a.ID, h)
			}
		}
	}

	seen := map[string]bool{}
	for _, b := range p.Banners {
		if !idRe.MatchString(b.ID) {
			add("banner %q: id must match %s", b.ID, idRe)
		}
		if seen[b.ID] {
			add("banner %q: duplicate id", b.ID)
		}
		seen[b.ID] = true
		if _, err := Regex(b.Regex); err != nil {
			add("banner %q: regex: %v", b.ID, err)
		}
		if !bannerKinds[b.Kind] {
			add("banner %q: kind %q must be library, automation or human", b.ID, b.Kind)
		}
		if b.Agent != "" && !agentIDs[b.Agent] {
			add("banner %q: unknown agent %q", b.ID, b.Agent)
		}
	}

	seen = map[string]bool{}
	styleIDs := map[string]bool{}
	for _, s := range p.Styles {
		if !idRe.MatchString(s.ID) || !strings.HasPrefix(s.ID, "style.") {
			add("style %q: id must match %s and start with \"style.\"", s.ID, idRe)
		}
		if seen[s.ID] {
			add("style %q: duplicate id", s.ID)
		}
		seen[s.ID] = true
		styleIDs[s.ID] = true
		if s.Group != "" {
			styleIDs["style."+s.Group] = true
		}
		if _, err := Regex(s.Regex); err != nil {
			add("style %q: regex: %v", s.ID, err)
		}
		if s.Weight < 1 || s.Weight > 50 {
			add("style %q: weight %d must be 1..50", s.ID, s.Weight)
		}
	}

	seen = map[string]bool{}
	for _, h := range p.APIHosts {
		k := hostKey(h)
		if seen[k] {
			add("api_host %s: duplicate", k)
		}
		seen[k] = true
		switch {
		case h.Host != "" && h.CIDR != "":
			add("api_host %s: set host or cidr, not both", k)
		case h.Host == "" && h.CIDR == "":
			add("api_host %s: host or cidr is required", k)
		case h.Host != "":
			if h.Host != strings.ToLower(h.Host) || strings.ContainsAny(h.Host, "/ :") {
				add("api_host %q: must be a lowercase host name without scheme or path", h.Host)
			}
			if _, err := path.Match(h.Host, ""); err != nil {
				add("api_host %q: bad wildcard pattern: %v", h.Host, err)
			}
		default:
			if _, _, err := net.ParseCIDR(h.CIDR); err != nil {
				add("api_host %q: cidr: %v", h.CIDR, err)
			}
		}
		if h.Port < 0 || h.Port > 65535 {
			add("api_host %s: port %d out of range", k, h.Port)
		}
		if h.Agent != "" && !agentIDs[h.Agent] {
			add("api_host %s: unknown agent %q", k, h.Agent)
		}
	}

	seen = map[string]bool{}
	for _, pr := range p.Profiles {
		if !idRe.MatchString(pr.ID) {
			add("profile %q: id must match %s", pr.ID, idRe)
		}
		if seen[pr.ID] {
			add("profile %q: duplicate id", pr.ID)
		}
		seen[pr.ID] = true
		for _, c := range pr.Match.SrcCIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				add("profile %q: src_cidrs %q: %v", pr.ID, c, err)
			}
		}
		if pr.Match.MinMatchRatio < 0 || pr.Match.MinMatchRatio > 1 {
			add("profile %q: min_match_ratio %v must be 0..1", pr.ID, pr.Match.MinMatchRatio)
		}
		for i, cl := range pr.Match.AnyOf {
			n := 0
			for name, re := range map[string]string{"cmd_regex": cl.CmdRegex, "argv0_regex": cl.Argv0Regex, "path_regex": cl.PathRegex, "banner_regex": cl.BannerRegex} {
				if re == "" {
					continue
				}
				n++
				if _, err := Regex(re); err != nil {
					add("profile %q: any_of[%d].%s: %v", pr.ID, i, name, err)
				}
			}
			if n == 0 {
				add("profile %q: any_of[%d] is empty", pr.ID, i)
			}
		}
		if pr.MaxScore < 0 || pr.MaxScore > 100 {
			add("profile %q: max_score %d must be 0..100", pr.ID, pr.MaxScore)
		}
		if len(pr.Suppress) == 0 && pr.MaxScore == 0 {
			add("profile %q: suppress list is empty and no max_score; profile does nothing", pr.ID)
		}
		for _, s := range pr.Suppress {
			if !knownSuppress(s, styleIDs) {
				add("profile %q: suppress %q is not a known clue id or category", pr.ID, s)
			}
			if protectedSuppress[s] && !pr.AllowAgentProcesses {
				add("profile %q: suppress %q requires allow_agent_processes: true", pr.ID, s)
			}
		}
	}
	return errs
}

// knownSuppress accepts a category, a spec clue id, a style id or group from
// the pack, or a dotted prefix of any of those ("rhythm", "banner.automation").
func knownSuppress(s string, styleIDs map[string]bool) bool {
	for _, c := range Categories {
		if s == c {
			return true
		}
	}
	for _, c := range KnownClues {
		if s == c || strings.HasPrefix(c, s+".") {
			return true
		}
	}
	if styleIDs[s] {
		return true
	}
	for id := range styleIDs {
		if strings.HasPrefix(id, s+".") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Lookups

// AgentByID returns the agent with the given id or nil.
func (p *Pack) AgentByID(id string) *Agent {
	for i := range p.Agents {
		if p.Agents[i].ID == id {
			return &p.Agents[i]
		}
	}
	return nil
}

// AgentForAIAgentValue maps a declared AI_AGENT value ("claude-code",
// "Cursor-CLI@1.2.0") to an agent id. The comparison is case-insensitive
// and ignores an "@version" suffix. Unknown values return "" so callers can
// still report the raw declaration.
func (p *Pack) AgentForAIAgentValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(v, '@'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return ""
	}
	for i := range p.Agents {
		for _, val := range p.Agents[i].EnvAIAgent {
			if strings.ToLower(val) == v {
				return p.Agents[i].ID
			}
		}
	}
	if a := p.AgentByID(v); a != nil {
		return a.ID
	}
	return ""
}

// BannerKind classifies a client software version string. banner may be the
// raw "SSH-2.0-…" identification or the sshd log form without the prefix.
// Returns empty strings when no rule matches.
func (p *Pack) BannerKind(banner string) (kind, id, agent string) {
	banner = strings.TrimSpace(banner)
	for i := range p.Banners {
		re, err := Regex(p.Banners[i].Regex)
		if err != nil {
			continue
		}
		if re.MatchString(banner) {
			return p.Banners[i].Kind, p.Banners[i].ID, p.Banners[i].Agent
		}
	}
	return "", "", ""
}

// StyleMatch is one style rule hit with the redacted fragment it matched.
type StyleMatch struct {
	Style    Style
	Fragment string
}

// StyleMatches returns every style rule matching cmd, with the matched
// fragment (bounded to 40 bytes) suitable for privacy-redacted evidence.
func (p *Pack) StyleMatches(cmd string) []StyleMatch {
	var out []StyleMatch
	for i := range p.Styles {
		re, err := Regex(p.Styles[i].Regex)
		if err != nil {
			continue
		}
		loc := re.FindStringIndex(cmd)
		if loc == nil {
			continue
		}
		frag := cmd[loc[0]:loc[1]]
		if len(frag) > 40 {
			frag = frag[:40] + "…"
		}
		out = append(out, StyleMatch{Style: p.Styles[i], Fragment: frag})
	}
	return out
}

// HostMatch finds the API host rule for a destination name and port
// (port 0 means 443). Names are compared lower-case; a rule host containing
// `*` is a path.Match wildcard pattern.
func (p *Pack) HostMatch(host string, port int) *Host {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil
	}
	if port == 0 {
		port = 443
	}
	for i := range p.APIHosts {
		h := &p.APIHosts[i]
		if h.Host == "" || effectivePort(h) != port {
			continue
		}
		if h.Host == host {
			return h
		}
		if strings.Contains(h.Host, "*") {
			if ok, _ := path.Match(h.Host, host); ok {
				return h
			}
		}
	}
	return nil
}

// HostMatchIP finds the API host rule whose CIDR contains ip at port.
func (p *Pack) HostMatchIP(ip string, port int) *Host {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil
	}
	if port == 0 {
		port = 443
	}
	for i := range p.APIHosts {
		h := &p.APIHosts[i]
		if h.CIDR == "" || effectivePort(h) != port {
			continue
		}
		pfx, err := netip.ParsePrefix(h.CIDR)
		if err != nil {
			continue
		}
		if pfx.Contains(addr.Unmap()) {
			return h
		}
	}
	return nil
}

func effectivePort(h *Host) int {
	if h.Port == 0 {
		return 443
	}
	return h.Port
}

// ProfileByID returns the allowlist profile with the given id or nil.
func (p *Pack) ProfileByID(id string) *Profile {
	for i := range p.Profiles {
		if p.Profiles[i].ID == id {
			return &p.Profiles[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Regex cache

var reCache sync.Map // pattern -> *regexp.Regexp

// Regex compiles pat once and caches it. Every regex in a pack goes through
// here so the detectors never recompile per event.
func Regex(pat string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(pat); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	reCache.Store(pat, re)
	return re, nil
}
