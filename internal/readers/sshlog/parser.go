// Package sshlog reads sshd log lines (journald via journalctl, or a syslog
// file) and turns them into event.Event values. The parsing here is portable
// and has no OS access; the sources in source_*.go feed it.
//
// Line formats follow docs/research/03-ssh-auditd-proc.md sections 1, 2 and 5.
package sshlog

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

// Source is the event.Event.Source value for everything this package emits.
const Source = "sshlog"

// Line is one sshd log record after the transport (syslog/journald) framing
// has been removed. Msg is the raw sshd message, still carrying any
// "debug1: " prefix or " [preauth]" suffix; ParseMessage handles those.
type Line struct {
	TS     time.Time
	Host   string
	Ident  string // sshd | sshd-session | sshd-auth
	PID    int    // 0 when the tag carried no pid
	Msg    string
	Cursor string // journald __CURSOR; empty for file sources
}

// validIdent lists the syslog identifiers sshd has used across versions:
// "sshd" (all versions, listener since 9.8), "sshd-session" (9.8+) and
// "sshd-auth" (10.0+ pre-auth process).
func validIdent(s string) bool {
	switch s {
	case "sshd", "sshd-session", "sshd-auth":
		return true
	}
	return false
}

// syslogTagRe matches "host ident[pid]: " or "host ident: " at the start of
// the remainder of a syslog line (after the timestamp).
var syslogTagRe = regexp.MustCompile(`^(\S+) ([A-Za-z0-9_.-]+)(?:\[(\d+)\])?: ?`)

// ParseSyslogLine parses one line of a syslog-format sshd log. Accepted
// timestamp shapes are the rsyslog traditional "Sep 11 14:03:22" (year taken
// from now, never more than a day in the future) and RFC 3339 / ISO 8601 with
// optional fractional seconds. It returns false for lines that are not from
// sshd, sshd-session or sshd-auth, or that do not look like syslog at all.
func ParseSyslogLine(s string, now time.Time) (Line, bool) {
	s = strings.TrimRight(s, "\r\n")
	if s == "" {
		return Line{}, false
	}
	var (
		ts   time.Time
		rest string
	)
	if sp := strings.IndexByte(s, ' '); sp > 0 && s[0] >= '0' && s[0] <= '9' {
		// RFC 3339 first: "2026-09-11T14:03:22.114532+00:00 host ...".
		t, err := time.Parse(time.RFC3339Nano, s[:sp])
		if err != nil {
			return Line{}, false
		}
		ts = t
		rest = s[sp+1:]
	} else {
		// Traditional: "Sep 11 14:03:22 " or "Sep  1 14:03:22 " (15 chars).
		if len(s) < 16 || s[15] != ' ' {
			return Line{}, false
		}
		t, err := time.Parse("Jan _2 15:04:05", s[:15])
		if err != nil {
			return Line{}, false
		}
		ts = inferYear(t, now)
		rest = s[16:]
	}

	m := syslogTagRe.FindStringSubmatch(rest)
	if m == nil || !validIdent(m[2]) {
		return Line{}, false
	}
	l := Line{TS: ts, Host: m[1], Ident: m[2], Msg: rest[len(m[0]):]}
	if m[3] != "" {
		l.PID, _ = strconv.Atoi(m[3])
	}
	return l, true
}

// inferYear places a year-less syslog timestamp in now's year, or the previous
// one if that would put it more than a day in the future (log written in
// December, read in January). The location of now is used so that a file
// written in local time is interpreted the way the machine that wrote it
// would.
func inferYear(t, now time.Time) time.Time {
	loc := now.Location()
	c := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	if c.After(now.Add(24 * time.Hour)) {
		c = time.Date(now.Year()-1, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	}
	return c
}

// ParseJournalJSON parses one object as printed by `journalctl -o json`. It
// returns false when the entry is not from an sshd identifier, when MESSAGE is
// not a string (journald emits an array of bytes for non-UTF-8 payloads; those
// are skipped rather than guessed at), or when the object is malformed.
func ParseJournalJSON(b []byte) (Line, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return Line{}, false
	}
	ident, ok := jsonString(m["SYSLOG_IDENTIFIER"])
	if !ok || !validIdent(ident) {
		return Line{}, false
	}
	msg, ok := jsonString(m["MESSAGE"])
	if !ok {
		return Line{}, false
	}
	l := Line{Ident: ident, Msg: msg}
	l.Host, _ = jsonString(m["_HOSTNAME"])
	l.Cursor, _ = jsonString(m["__CURSOR"])
	if p, ok := jsonString(m["SYSLOG_PID"]); ok && p != "" {
		l.PID, _ = strconv.Atoi(p)
	} else if p, ok := jsonString(m["_PID"]); ok {
		l.PID, _ = strconv.Atoi(p)
	}
	if rt, ok := jsonString(m["__REALTIME_TIMESTAMP"]); ok {
		if us, err := strconv.ParseInt(rt, 10, 64); err == nil {
			l.TS = time.UnixMicro(us).UTC()
		}
	}
	return l, true
}

// jsonString returns a JSON string value, or the literal text of a number
// (journald prints numeric fields as strings, but tolerate numbers too).
// Arrays, objects, null and missing fields yield false.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", false
		}
		return s, true
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return string(raw), true
	}
	return "", false
}

// Message regexes, compiled once. Anchored so that text captured from one
// message can never be mistaken for another message.
var (
	rePrefix = regexp.MustCompile(`^(?:debug[123]|error|fatal): `)
	reSuffix = regexp.MustCompile(` \[(?:pre|post)auth\]$`)

	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+) ssh2(?:: (\S+) (\S+)(.*))?$`)
	reCertRest = regexp.MustCompile(`^ ID (.+) \(serial (\d+)\) CA (\S+) (\S+)$`)

	reFailed      = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+) ssh2(?:: (\S+) (\S+))?$`)
	reInvalidUser = regexp.MustCompile(`^Invalid user (\S*) from (\S+) port (\d+)$`)
	reClosedAuth  = regexp.MustCompile(`^Connection closed by (authenticating|invalid) user (\S+) (\S+) port (\d+)$`)
	reDisconAuth  = regexp.MustCompile(`^Disconnected from (authenticating|invalid) user (\S+) (\S+) port (\d+)$`)
	reTimeout     = regexp.MustCompile(`^Timeout before authentication for (\S+?)(?: port (\d+))?(?:, pid = (\d+))?$`)
	reMaxAuth     = regexp.MustCompile(`^maximum authentication attempts exceeded for (invalid user )?(\S+) from (\S+) port (\d+) ssh2$`)
	rePAMFail     = regexp.MustCompile(`^PAM: Authentication failure for (illegal user )?(\S+) from (\S+)$`)

	reStartSession = regexp.MustCompile(`^Starting session: (shell|command|subsystem '([^']*)'|forced-command \((config|key-option)\) '(.*)')(?: on (pts/\d+))? for (\S+) from (\S+) port (\d+) id (\d+)$`)
	reCloseSession = regexp.MustCompile(`^Close session: user (\S+) from (\S+) port (\d+) id (\d+)$`)

	reDisconUser  = regexp.MustCompile(`^Disconnected from user (\S+) (\S+) port (\d+)$`)
	reDiscon      = regexp.MustCompile(`^Disconnected from (\S+) port (\d+)$`)
	reRecvDiscon  = regexp.MustCompile(`^Received disconnect from (\S+) port (\d+):(\d+):(?: (.*))?$`)
	reConnClosed  = regexp.MustCompile(`^Connection closed by (\S+) port (\d+)$`)
	reConnReset   = regexp.MustCompile(`^Connection reset by (\S+) port (\d+)$`)
	reUserChild   = regexp.MustCompile(`^User child is on pid (\d+)$`)
	rePAMOpen     = regexp.MustCompile(`^pam_unix\(sshd:session\): session opened for user (\S+?)(?:\(uid=(\d+)\))? by (\S*)\(uid=(\d+)\)$`)
	rePAMClose    = regexp.MustCompile(`^pam_unix\(sshd:session\): session closed for user (\S+)$`)
	reBanner      = regexp.MustCompile(`^(?:Remote protocol version ([\d.]+), remote software version|Client protocol version ([\d.]+); client software version) (.+)$`)
	reSetEnv      = regexp.MustCompile(`^Setting env (\d+): ([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	reIgnoreEnv   = regexp.MustCompile(`^Ignoring env request (\S+): (disallowed name|too many env vars)$`)
	reNotMatchLog = regexp.MustCompile(`\n|\r`) // multi-line payloads are never valid sshd messages
)

// ParseMessage classifies the sshd message in l and builds the event. It
// returns false for messages the correlator has no use for (kex noise,
// "Server listening", "Connection from", …).
//
// Every event carries TS, PID, Source "sshlog" and Fields ident/host. The
// remaining Fields keys per Kind are:
//
//	ssh.auth_ok        method, submethod, keytype, fp, cert_id, cert_serial, ca_keytype, ca_fp
//	ssh.auth_fail      reason (failed|invalid_user|closed_authenticating|closed_invalid|
//	                   disconnected_authenticating|disconnected_invalid|timeout|max_attempts|pam),
//	                   method, keytype, fp, invalid_user=true, child_pid
//	ssh.session_start  stype (shell|command|subsystem|forced-command), subsystem, cmd, forced_by, tty, chan
//	ssh.disconnect     scope (connection|channel|pam), reason (disconnected|received_disconnect|closed|reset),
//	                   code, text, chan
//	ssh.pam_open       uid, by, by_uid            (pam_unix session opened)
//	                   note=user_child, child_pid (informational "User child is on pid N")
//	ssh.banner         banner, protocol
//	ssh.env            index, name, value | name, ignored=true, reason
func ParseMessage(l Line) (event.Event, bool) {
	msg := l.Msg
	if reNotMatchLog.MatchString(msg) {
		return event.Event{}, false
	}
	msg = rePrefix.ReplaceAllString(msg, "")
	msg = reSuffix.ReplaceAllString(msg, "")

	ev := event.Event{TS: l.TS, Source: Source, PID: l.PID}
	ev.Set("ident", l.Ident)
	if l.Host != "" {
		ev.Set("host", l.Host)
	}

	switch {
	case strings.HasPrefix(msg, "Accepted "):
		m := reAccepted.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthOK
		ev.User, ev.SrcIP, ev.SrcPort = m[2], m[3], atoi(m[4])
		method, sub, _ := strings.Cut(m[1], "/")
		ev.Set("method", method)
		if sub != "" {
			ev.Set("submethod", sub)
		}
		if m[5] != "" {
			ev.Set("keytype", m[5]).Set("fp", m[6])
			if strings.HasSuffix(m[5], "-CERT") {
				if c := reCertRest.FindStringSubmatch(m[7]); c != nil {
					ev.Set("cert_id", c[1]).Set("cert_serial", c[2]).Set("ca_keytype", c[3]).Set("ca_fp", c[4])
				}
			}
		}
		return ev, true

	case strings.HasPrefix(msg, "Failed "):
		m := reFailed.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthFail
		ev.User, ev.SrcIP, ev.SrcPort = m[3], m[4], atoi(m[5])
		method, sub, _ := strings.Cut(m[1], "/")
		ev.Set("reason", "failed").Set("method", method)
		if sub != "" {
			ev.Set("submethod", sub)
		}
		if m[2] != "" {
			ev.Set("invalid_user", "true")
		}
		if m[6] != "" {
			ev.Set("keytype", m[6]).Set("fp", m[7])
		}
		return ev, true

	case strings.HasPrefix(msg, "Invalid user "):
		m := reInvalidUser.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthFail
		ev.User, ev.SrcIP, ev.SrcPort = m[1], m[2], atoi(m[3])
		ev.Set("reason", "invalid_user").Set("invalid_user", "true")
		return ev, true

	case strings.HasPrefix(msg, "Connection closed by "):
		if m := reClosedAuth.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHAuthFail
			ev.User, ev.SrcIP, ev.SrcPort = m[2], m[3], atoi(m[4])
			ev.Set("reason", "closed_"+m[1])
			if m[1] == "invalid" {
				ev.Set("invalid_user", "true")
			}
			return ev, true
		}
		if m := reConnClosed.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHDisconnect
			ev.SrcIP, ev.SrcPort = m[1], atoi(m[2])
			ev.Set("scope", "connection").Set("reason", "closed")
			return ev, true
		}
		return event.Event{}, false

	case strings.HasPrefix(msg, "Connection reset by "):
		m := reConnReset.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHDisconnect
		ev.SrcIP, ev.SrcPort = m[1], atoi(m[2])
		ev.Set("scope", "connection").Set("reason", "reset")
		return ev, true

	case strings.HasPrefix(msg, "Timeout before authentication for "):
		m := reTimeout.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthFail
		ev.SrcIP, ev.SrcPort = m[1], atoi(m[2])
		ev.Set("reason", "timeout")
		if m[3] != "" {
			ev.Set("child_pid", m[3])
		}
		return ev, true

	case strings.HasPrefix(msg, "maximum authentication attempts exceeded for "):
		m := reMaxAuth.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthFail
		ev.User, ev.SrcIP, ev.SrcPort = m[2], m[3], atoi(m[4])
		ev.Set("reason", "max_attempts")
		if m[1] != "" {
			ev.Set("invalid_user", "true")
		}
		return ev, true

	case strings.HasPrefix(msg, "PAM: Authentication failure for "):
		m := rePAMFail.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHAuthFail
		ev.User, ev.SrcIP = m[2], m[3]
		ev.Set("reason", "pam")
		if m[1] != "" {
			ev.Set("invalid_user", "true")
		}
		return ev, true

	case strings.HasPrefix(msg, "Starting session: "):
		m := reStartSession.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHSessionStart
		ev.User, ev.SrcIP, ev.SrcPort = m[6], m[7], atoi(m[8])
		ev.Set("chan", m[9])
		switch {
		case m[1] == "shell", m[1] == "command":
			ev.Set("stype", m[1])
		case strings.HasPrefix(m[1], "subsystem "):
			ev.Set("stype", "subsystem").Set("subsystem", m[2])
		default: // forced-command (config|key-option) '...'
			ev.Set("stype", "forced-command").Set("forced_by", m[3]).Set("cmd", m[4])
		}
		if m[5] != "" {
			ev.Set("tty", m[5])
		}
		return ev, true

	case strings.HasPrefix(msg, "Close session: "):
		m := reCloseSession.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		// Channel close, not connection end. scope=channel lets the
		// correlator ignore it (or pair it with session_start by chan).
		ev.Kind = event.SSHDisconnect
		ev.User, ev.SrcIP, ev.SrcPort = m[1], m[2], atoi(m[3])
		ev.Set("scope", "channel").Set("chan", m[4])
		return ev, true

	case strings.HasPrefix(msg, "Disconnected from "):
		if m := reDisconUser.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHDisconnect
			ev.User, ev.SrcIP, ev.SrcPort = m[1], m[2], atoi(m[3])
			ev.Set("scope", "connection").Set("reason", "disconnected")
			return ev, true
		}
		if m := reDisconAuth.FindStringSubmatch(msg); m != nil {
			// Pre-auth end of connection: same family as
			// "Connection closed by authenticating user".
			ev.Kind = event.SSHAuthFail
			ev.User, ev.SrcIP, ev.SrcPort = m[2], m[3], atoi(m[4])
			ev.Set("reason", "disconnected_"+m[1])
			if m[1] == "invalid" {
				ev.Set("invalid_user", "true")
			}
			return ev, true
		}
		if m := reDiscon.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHDisconnect
			ev.SrcIP, ev.SrcPort = m[1], atoi(m[2])
			ev.Set("scope", "connection").Set("reason", "disconnected")
			return ev, true
		}
		return event.Event{}, false

	case strings.HasPrefix(msg, "Received disconnect from "):
		m := reRecvDiscon.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHDisconnect
		ev.SrcIP, ev.SrcPort = m[1], atoi(m[2])
		// m[4] is text chosen by the remote client: stored as data only.
		ev.Set("scope", "connection").Set("reason", "received_disconnect").Set("code", m[3]).Set("text", m[4])
		return ev, true

	case strings.HasPrefix(msg, "Connection from "):
		// Pre-auth, carries no user. The correlator keys on Accepted, which
		// repeats (ip, port) under the same PID, so nothing is emitted.
		return event.Event{}, false

	case strings.HasPrefix(msg, "User child is on pid "):
		m := reUserChild.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		// The contract has no Kind for this line. It is emitted as an
		// informational ssh.pam_open with note=user_child so the correlator
		// can learn the post-auth child PID (the PID that logs Starting
		// session/Disconnected on OpenSSH <= 9.7). Consumers must check
		// note before treating a pam_open as a PAM session open.
		ev.Kind = event.SSHPAMOpen
		ev.Set("note", "user_child").Set("child_pid", m[1])
		return ev, true

	case strings.HasPrefix(msg, "pam_unix(sshd:session): "):
		if m := rePAMOpen.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHPAMOpen
			ev.User = m[1]
			if m[2] != "" {
				ev.Set("uid", m[2])
			}
			if m[3] != "" {
				ev.Set("by", m[3])
			}
			ev.Set("by_uid", m[4])
			return ev, true
		}
		if m := rePAMClose.FindStringSubmatch(msg); m != nil {
			ev.Kind = event.SSHDisconnect
			ev.User = m[1]
			ev.Set("scope", "pam")
			return ev, true
		}
		return event.Event{}, false

	case strings.HasPrefix(msg, "Remote protocol version "), strings.HasPrefix(msg, "Client protocol version "):
		m := reBanner.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHBanner
		proto := m[1]
		if proto == "" {
			proto = m[2]
		}
		ev.Set("banner", strings.TrimSpace(m[3])).Set("protocol", proto)
		return ev, true

	case strings.HasPrefix(msg, "Setting env "):
		m := reSetEnv.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHEnv
		ev.Set("index", m[1]).Set("name", m[2]).Set("value", m[3])
		return ev, true

	case strings.HasPrefix(msg, "Ignoring env request "):
		m := reIgnoreEnv.FindStringSubmatch(msg)
		if m == nil {
			return event.Event{}, false
		}
		ev.Kind = event.SSHEnv
		ev.Set("name", m[1]).Set("ignored", "true").Set("reason", m[2])
		return ev, true
	}
	return event.Event{}, false
}

// atoi is strconv.Atoi for digit-only captures; a failure yields 0.
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
