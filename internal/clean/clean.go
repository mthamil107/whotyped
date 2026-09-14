// Package clean sanitises attacker-controlled strings at ingestion: process
// names, executable paths and the AI_AGENT declaration all come from an
// environment the monitored user controls, and they end up in alerts,
// terminal output and Slack cards. Everything here is stdlib-only and safe to
// call from any reader or the correlator.
package clean

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Size caps applied by the readers and the correlator.
const (
	MaxComm    = 64  // /proc comm and auditd comm=
	MaxName    = 256 // argv0 and exe paths
	MaxAIAgent = 64  // AI_AGENT declaration
)

// InvalidDeclaration replaces an AI_AGENT value that is too long or carries
// characters outside the allowed set. It is recorded on the ProcSample so an
// operator can see that something tried to declare, but it never becomes a
// declaration.
const InvalidDeclaration = "invalid-declaration"

// Text strips ANSI escape sequences, replaces every other control or
// non-printable rune with '?', and caps the result at max bytes without
// splitting a UTF-8 sequence. Tabs and newlines count as control characters:
// a comm containing a newline is a log-line injection attempt, not a name.
func Text(s string, max int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == 0x1b { // ESC: skip the whole sequence
			i += skipEscape(s[i:])
			continue
		}
		if r == utf8.RuneError && size == 1 || unicode.IsControl(r) || !unicode.IsPrint(r) {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return Truncate(b.String(), max)
}

// skipEscape returns the byte length of the escape sequence starting at s[0]
// (an ESC). CSI sequences end at a byte in 0x40..0x7e; OSC sequences end at
// BEL or ST (ESC \); a bare ESC followed by one byte is a two-byte sequence.
func skipEscape(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	switch s[1] {
	case '[': // CSI
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return len(s)
	case ']': // OSC
		for i := 2; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == 0x5c { // ESC \ (ST)
				return i + 2
			}
		}
		return len(s)
	}
	return 2
}

// Truncate caps s at max bytes on a rune boundary. max <= 0 means no cap.
func Truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// AIAgent validates a declared agent name: at most MaxAIAgent bytes drawn
// from [A-Za-z0-9._@:+-]. ok is false when the value is rejected; the
// returned string is then InvalidDeclaration so callers can still record that
// a declaration was attempted. An empty value is not a declaration at all.
func AIAgent(v string) (name string, ok bool) {
	if v == "" {
		return "", false
	}
	if len(v) > MaxAIAgent {
		return InvalidDeclaration, false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '@', c == ':', c == '+', c == '-':
		default:
			return InvalidDeclaration, false
		}
	}
	return v, true
}
