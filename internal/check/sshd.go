package check

import (
	"bufio"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// SSHDSettings is what whotyped needs to know from sshd_config (or from
// `sshd -T` output, which uses the same keyword-value format).
type SSHDSettings struct {
	LogLevel              string   // upper-cased; "" when unset (sshd defaults to INFO)
	AcceptEnv             []string // every pattern from every global AcceptEnv line
	PermitUserEnvironment string   // first value seen, "" when unset
	Includes              []string // Include patterns encountered, as written
	Unresolved            []string // Include patterns that could not be expanded (no FS)
	Files                 []string // files parsed, in order
	MatchSeen             bool     // a Match block was encountered; later lines were conditional
}

// EffectiveLogLevel returns LogLevel or sshd's default INFO.
func (s SSHDSettings) EffectiveLogLevel() string {
	if s.LogLevel == "" {
		return "INFO"
	}
	return s.LogLevel
}

// logLevelRank orders sshd log levels; DEBUG == DEBUG1.
func logLevelRank(level string) int {
	switch strings.ToUpper(level) {
	case "QUIET":
		return 0
	case "FATAL":
		return 1
	case "ERROR":
		return 2
	case "INFO":
		return 3
	case "VERBOSE":
		return 4
	case "DEBUG", "DEBUG1":
		return 5
	case "DEBUG2":
		return 6
	case "DEBUG3":
		return 7
	}
	return -1
}

// AtLeastVerbose reports whether "Starting session" lines are logged.
func (s SSHDSettings) AtLeastVerbose() bool { return logLevelRank(s.EffectiveLogLevel()) >= 4 }

// AtLeastDebug1 reports whether client banners are logged.
func (s SSHDSettings) AtLeastDebug1() bool { return logLevelRank(s.EffectiveLogLevel()) >= 5 }

// AcceptsEnv reports whether name would pass AcceptEnv. sshd matches each
// pattern with `*` and `?` wildcards; a leading `!` negates (rare).
func (s SSHDSettings) AcceptsEnv(name string) bool {
	accepted := false
	for _, pat := range s.AcceptEnv {
		neg := strings.HasPrefix(pat, "!")
		pat = strings.TrimPrefix(pat, "!")
		ok, err := path.Match(pat, name)
		if err != nil || !ok {
			continue
		}
		if neg {
			return false
		}
		accepted = true
	}
	return accepted
}

// AcceptsAIAgent is AcceptsEnv("AI_AGENT").
func (s SSHDSettings) AcceptsAIAgent() bool { return s.AcceptsEnv("AI_AGENT") }

// ParseSSHDConfig parses one sshd_config stream without expanding Include
// directives (they are recorded in Includes and Unresolved). Keywords are
// case-insensitive, the first occurrence of a keyword wins, AcceptEnv
// accumulates, and settings after the first Match block are ignored unless
// a `Match all` returns to the global section.
func ParseSSHDConfig(r io.Reader) SSHDSettings {
	p := &sshdParser{}
	p.parse(r, "<reader>")
	return p.s
}

// ParseSSHDConfigFS parses name (an fs path such as "etc/ssh/sshd_config")
// and expands Include globs against fsys. Include patterns are resolved
// like sshd does: relative ones against /etc/ssh. A missing main file is
// an error; an Include that matches nothing is not.
func ParseSSHDConfigFS(fsys fs.FS, name string) (SSHDSettings, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return SSHDSettings{}, err
	}
	defer f.Close()
	p := &sshdParser{fsys: fsys}
	p.parse(f, name)
	return p.s, nil
}

type sshdParser struct {
	s       SSHDSettings
	fsys    fs.FS
	inMatch bool
	depth   int
	seen    map[string]bool // keywords already set (first wins)
}

const maxIncludeDepth = 16

func (p *sshdParser) parse(r io.Reader, name string) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	p.s.Files = append(p.s.Files, name)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value := splitKeyword(line)
		if keyword == "" {
			continue
		}
		switch keyword {
		case "include":
			p.include(value)
		case "match":
			p.s.MatchSeen = true
			p.inMatch = !strings.EqualFold(strings.TrimSpace(value), "all")
		default:
			if p.inMatch {
				continue
			}
			p.set(keyword, value)
		}
	}
}

// splitKeyword returns the lower-cased keyword and the raw value. sshd
// accepts "Key value", "Key=value" and "Key = value".
func splitKeyword(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	keyword := strings.ToLower(line[:i])
	value := strings.TrimLeft(line[i:], " \t")
	value = strings.TrimPrefix(value, "=")
	return keyword, strings.TrimSpace(value)
}

// fields splits a value on whitespace, honouring double quotes.
func fields(value string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range value {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func (p *sshdParser) set(keyword, value string) {
	switch keyword {
	case "acceptenv":
		p.s.AcceptEnv = append(p.s.AcceptEnv, fields(value)...)
	case "loglevel":
		if !p.seen[keyword] {
			p.s.LogLevel = strings.ToUpper(strings.Trim(value, `"`))
		}
	case "permituserenvironment":
		if !p.seen[keyword] {
			p.s.PermitUserEnvironment = strings.Trim(value, `"`)
		}
	default:
		return
	}
	p.seen[keyword] = true
}

func (p *sshdParser) include(value string) {
	for _, pat := range fields(value) {
		p.s.Includes = append(p.s.Includes, pat)
		if p.inMatch {
			// Included content would sit under the Match; nothing global to learn.
			continue
		}
		if p.fsys == nil || p.depth >= maxIncludeDepth {
			p.s.Unresolved = append(p.s.Unresolved, pat)
			continue
		}
		abs := pat
		if !strings.HasPrefix(abs, "/") {
			abs = "/etc/ssh/" + abs
		}
		matches, err := fs.Glob(p.fsys, strings.TrimPrefix(abs, "/"))
		if err != nil {
			p.s.Unresolved = append(p.s.Unresolved, pat)
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			f, err := p.fsys.Open(m)
			if err != nil {
				p.s.Unresolved = append(p.s.Unresolved, m)
				continue
			}
			if st, err := f.Stat(); err == nil && st.IsDir() {
				f.Close()
				continue
			}
			p.depth++
			savedMatch := p.inMatch
			p.parse(f, m)
			// A Match block inside an included file ends with that file.
			p.inMatch = savedMatch
			p.depth--
			f.Close()
		}
	}
}
