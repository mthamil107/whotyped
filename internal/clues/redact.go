package clues

import (
	"strconv"
	"strings"
	"unicode"
)

// maxFragment bounds the matched fragment quoted in evidence strings.
const maxFragment = 48

// Redact renders a command line for evidence according to the privacy mode:
//
//	redacted (default)  argv0 plus the length, e.g. "git … (len 142)"
//	full                the whole command (operator opted in)
//	none                nothing at all
//
// Evidence built by detectors never includes the full command; this helper is
// for callers (alerts, reports) that want to show the line under policy.
func Redact(cmd, mode string) string {
	cmd = clean(cmd)
	switch mode {
	case "full":
		return cmd
	case "none":
		return ""
	}
	if cmd == "" {
		return ""
	}
	argv0 := cmd
	if i := strings.IndexFunc(cmd, unicode.IsSpace); i >= 0 {
		argv0 = cmd[:i]
	}
	if len(argv0) > maxFragment {
		argv0 = argv0[:maxFragment] + "…"
	}
	return argv0 + " … (len " + strconv.Itoa(len(cmd)) + ")"
}

// Fragment returns the part of cmd worth quoting in evidence for a match:
// the match itself, trimmed, with control characters removed and cut to
// maxFragment bytes. It never returns the whole command unless the command is
// itself shorter than the limit and equal to the match.
func Fragment(cmd, match string) string {
	m := strings.TrimLeft(clean(match), " ;&|") // regexes often anchor on the preceding operator
	if m == "" {
		m = clean(cmd)
		if i := strings.IndexFunc(m, unicode.IsSpace); i >= 0 {
			m = m[:i]
		}
	}
	if len(m) > maxFragment {
		m = truncate(m, maxFragment)
	}
	return m
}

// clean collapses newlines/tabs and drops control characters so evidence can
// never smuggle a fake log line into a sink (log-line injection defence).
func clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range strings.TrimSpace(s) {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		if unicode.IsControl(r) {
			continue
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncate cuts s to at most n bytes on a rune boundary and appends an ellipsis.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
