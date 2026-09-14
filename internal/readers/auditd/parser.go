// Package auditd reads Linux audit records (audit.log or the audisp socket),
// groups them into events and emits audit.execve / audit.login / audit.logout.
//
// Record parsing and grouping are portable and fixture-tested; only the file
// inode lookup and the af_unix dial are Linux-specific.
package auditd

import (
	"encoding/hex"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mthamil107/whotyped/internal/event"
)

// Record is one parsed audit line. Fields holds the k=v pairs of the record
// body with hex values decoded and a nested msg='…' flattened into the same
// map. Enriched holds the ENRICHED tail (after 0x1D) verbatim, quotes removed.
type Record struct {
	Type     string
	TS       time.Time
	Serial   uint64
	Fields   map[string]string
	Enriched map[string]string
}

// Stats counts what the parser has seen. Events counts emitted events only;
// records of ignored types are counted in Records but not in Events.
type Stats struct {
	Lines, Records, Events, Malformed uint64
}

// enrichedSep separates the raw record from the ENRICHED tail (log_format = ENRICHED).
const enrichedSep = "\x1d"

// Field caps so a pathological argv cannot bloat state or alerts: the joined
// command line, the first argument / executable path, and the kernel comm
// (which is 16 bytes on Linux; 64 leaves room for hex-decoded junk).
const (
	maxCmdLen  = 2048
	maxNameLen = 256
	maxCommLen = 64
)

// ParseRecord parses one audit line. ok is false when the line is not an
// audit record (no type=/msg=audit header). The line may carry an optional
// leading "node=HOST " (ausearch / remote logging).
func ParseRecord(line string) (Record, bool) {
	line = strings.TrimRight(line, "\r\n")
	var rec Record
	raw, tail, hasTail := strings.Cut(line, enrichedSep)

	rest := raw
	if strings.HasPrefix(rest, "node=") {
		_, rest, _ = strings.Cut(rest, " ")
	}
	if !strings.HasPrefix(rest, "type=") {
		return rec, false
	}
	typ, rest, ok := strings.Cut(rest[len("type="):], " ")
	if !ok || !strings.HasPrefix(rest, "msg=audit(") {
		return rec, false
	}
	stamp, rest, ok := strings.Cut(rest[len("msg=audit("):], "):")
	if !ok {
		return rec, false
	}
	secs, serial, ok := strings.Cut(stamp, ":")
	if !ok {
		return rec, false
	}
	ts, ok := parseStamp(secs)
	if !ok {
		return rec, false
	}
	n, err := strconv.ParseUint(serial, 10, 64)
	if err != nil {
		return rec, false
	}
	rec.Type = typ
	rec.TS = ts
	rec.Serial = n
	rec.Fields = map[string]string{}
	parsePairs(strings.TrimSpace(rest), typ, rec.Fields, true)
	normaliseUnset(rec.Fields)
	if hasTail {
		rec.Enriched = map[string]string{}
		parsePairs(strings.TrimSpace(tail), typ, rec.Enriched, false)
	}
	return rec, true
}

// parseStamp converts "SECS.MSEC" to a UTC time.
func parseStamp(s string) (time.Time, bool) {
	secStr, msStr, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var ms int64
	if msStr != "" {
		ms, err = strconv.ParseInt(msStr, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
	}
	return time.Unix(sec, ms*int64(time.Millisecond)).UTC(), true
}

// parsePairs tokenises "k=v k="v v" k='nested k=v' k=HEX" into dst. A
// single-quoted value (the PAM msg='…' envelope) is parsed recursively and its
// pairs are flattened into dst. decode enables hex decoding for known string
// keys; the ENRICHED tail is never hex-encoded.
func parsePairs(s, typ string, dst map[string]string, decode bool) {
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			return
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			return
		}
		key := s[i : i+eq]
		if strings.IndexByte(key, ' ') >= 0 {
			// A bare token without '=' (e.g. a stray word): skip it.
			sp := strings.IndexByte(key, ' ')
			i += sp + 1
			continue
		}
		i += eq + 1
		if i >= len(s) {
			dst[key] = ""
			return
		}
		switch s[i] {
		case '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				dst[key] = s[i+1:]
				return
			}
			dst[key] = s[i+1 : i+1+end]
			i += end + 2
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				end = len(s) - i - 1
			}
			inner := s[i+1 : i+1+end]
			if key == "msg" {
				// Nested PAM envelope: flatten op=, acct=, addr=, terminal=, res=, …
				parsePairs(inner, typ, dst, decode)
			} else {
				dst[key] = inner
			}
			i += end + 2
		default:
			end := strings.IndexByte(s[i:], ' ')
			if end < 0 {
				end = len(s) - i
			}
			val := s[i : i+end]
			if decode && isHexKey(key, typ) && isHexValue(val) {
				if b, err := hex.DecodeString(val); err == nil {
					val = string(b)
				}
			}
			dst[key] = val
			i += end
		}
	}
}

// isHexKey reports whether key may carry a hex-encoded string value. Numeric
// keys (pid, ses, auid, …) are never decoded; aN is decoded only in EXECVE
// records because in SYSCALL records aN are pointer values.
func isHexKey(key, typ string) bool {
	switch key {
	case "proctitle", "cmd", "cwd", "name", "acct", "comm", "exe", "key", "hostname", "terminal", "grantors", "data":
		return true
	}
	if typ == "EXECVE" && isArgKey(key) {
		return true
	}
	return false
}

// isArgKey matches a0..aN and the chunked form aN[k].
func isArgKey(key string) bool {
	if len(key) < 2 || key[0] != 'a' {
		return false
	}
	rest := key[1:]
	if br := strings.IndexByte(rest, '['); br >= 0 {
		if !strings.HasSuffix(rest, "]") {
			return false
		}
		return allDigits(rest[:br]) && allDigits(rest[br+1:len(rest)-1])
	}
	return allDigits(rest)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isHexValue implements the kernel's rule: whole value, uppercase hex, even length.
func isHexValue(v string) bool {
	if len(v) < 2 || len(v)%2 != 0 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// normaliseUnset maps the kernel's "unset" loginuid/session id to -1.
func normaliseUnset(f map[string]string) {
	for _, k := range []string{"auid", "ses"} {
		if v, ok := f[k]; ok && (v == "unset" || v == "4294967295" || v == "-1") {
			f[k] = "-1"
		}
	}
}

// execveSyscalls maps arch → execve/execveat syscall numbers (research doc §3).
var execveSyscalls = map[string]map[string]bool{
	"c000003e": {"59": true, "322": true},  // x86_64
	"40000003": {"11": true, "358": true},  // i386
	"c00000b7": {"221": true, "281": true}, // aarch64
}

// isExecve decides whether a SYSCALL record is an execve/execveat.
func isExecve(sc Record) bool {
	if sc.Type != "SYSCALL" {
		return false
	}
	if name := sc.Enriched["SYSCALL"]; name == "execve" || name == "execveat" {
		return true
	}
	if nums, ok := execveSyscalls[strings.ToLower(sc.Fields["arch"])]; ok {
		return nums[sc.Fields["syscall"]]
	}
	return false
}

// argvFromExecve assembles argv from one or more EXECVE records of the same
// event, joining chunked arguments (aN_len= aN[0]= aN[1]=) in order.
func argvFromExecve(recs []Record) (argv []string, argc string) {
	merged := map[string]string{}
	for _, r := range recs {
		for k, v := range r.Fields {
			merged[k] = v
		}
	}
	argc = merged["argc"]
	type chunk struct {
		idx int
		val string
	}
	args := map[int]string{}
	chunks := map[int][]chunk{}
	maxIdx := -1
	for k, v := range merged {
		if !isArgKey(k) {
			continue
		}
		rest := k[1:]
		if br := strings.IndexByte(rest, '['); br >= 0 {
			n, _ := strconv.Atoi(rest[:br])
			c, _ := strconv.Atoi(rest[br+1 : len(rest)-1])
			chunks[n] = append(chunks[n], chunk{c, v})
			if n > maxIdx {
				maxIdx = n
			}
			continue
		}
		n, _ := strconv.Atoi(rest)
		args[n] = v
		if n > maxIdx {
			maxIdx = n
		}
	}
	for n, cs := range chunks {
		sort.Slice(cs, func(i, j int) bool { return cs[i].idx < cs[j].idx })
		var b strings.Builder
		for _, c := range cs {
			b.WriteString(c.val)
		}
		args[n] = b.String()
	}
	if maxIdx < 0 {
		return nil, argc
	}
	argv = make([]string, maxIdx+1)
	for n, v := range args {
		argv[n] = v
	}
	return argv, argc
}

// Parser groups records by (TS, Serial) and turns complete groups into events.
// It is not safe for concurrent use; Stats may be read from any goroutine.
type Parser struct {
	// MaxAge is how long an open group may wait for more records before
	// Flush closes it. Zero means 2s.
	MaxAge time.Duration
	// Now supplies wall-clock time for group ageing (tests inject a fake clock).
	Now func() time.Time

	groups map[groupKey]*group
	order  []groupKey // insertion order, so flushes emit oldest first

	lines, records, events, malformed atomic.Uint64
}

type groupKey struct {
	ts     int64 // unix nanos
	serial uint64
}

type group struct {
	key     groupKey
	records []Record
	seen    time.Time // wall clock when the first record arrived
}

// NewParser returns a Parser with default ageing (2s, time.Now).
func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Parser) maxAge() time.Duration {
	if p.MaxAge > 0 {
		return p.MaxAge
	}
	return 2 * time.Second
}

// Stats returns a snapshot of the counters.
func (p *Parser) Stats() Stats {
	return Stats{
		Lines:     p.lines.Load(),
		Records:   p.records.Load(),
		Events:    p.events.Load(),
		Malformed: p.malformed.Load(),
	}
}

// Feed parses one line and returns any events completed by it. A group is
// closed by an EOE record, by a PROCTITLE record (always the last record of a
// syscall event), when a record two or more serials ahead arrives (adjacent
// events may interleave in audit.log), or by Flush after MaxAge. Records of
// single-record types (USER_*, CRED_*, LOGIN, …) are emitted at once.
func (p *Parser) Feed(line string) []event.Event {
	p.lines.Add(1)
	if strings.TrimSpace(line) == "" {
		return nil
	}
	rec, ok := ParseRecord(line)
	if !ok {
		p.malformed.Add(1)
		return nil
	}
	p.records.Add(1)
	if p.groups == nil {
		p.groups = map[groupKey]*group{}
	}
	key := groupKey{rec.TS.UnixNano(), rec.Serial}

	var out []event.Event
	// Close groups that are clearly behind the stream. The stale keys are
	// collected first because close mutates p.order; on the normal path of
	// zero or one open group nothing is allocated per line.
	var stale []groupKey
	for _, k := range p.order {
		if k.serial+1 < rec.Serial {
			stale = append(stale, k)
		}
	}
	for _, k := range stale {
		out = append(out, p.close(k)...)
	}

	if rec.Type == "EOE" {
		return append(out, p.close(key)...)
	}
	if isSingleRecordType(rec.Type) {
		if ev, ok := p.build(key, []Record{rec}); ok {
			out = append(out, ev)
		}
		return out
	}
	g := p.groups[key]
	if g == nil {
		g = &group{key: key, seen: p.now()}
		p.groups[key] = g
		p.order = append(p.order, key)
	}
	g.records = append(g.records, rec)
	if rec.Type == "PROCTITLE" {
		out = append(out, p.close(key)...)
	}
	return out
}

// Flush closes groups older than MaxAge as of now. Call it periodically from
// the tailer so the last event before a quiet period is not delayed forever.
func (p *Parser) Flush(now time.Time) []event.Event {
	var out []event.Event
	for _, k := range append([]groupKey(nil), p.order...) {
		g := p.groups[k]
		if g != nil && now.Sub(g.seen) >= p.maxAge() {
			out = append(out, p.close(k)...)
		}
	}
	return out
}

// FlushAll closes every open group regardless of age (end of replay).
func (p *Parser) FlushAll() []event.Event {
	var out []event.Event
	for _, k := range append([]groupKey(nil), p.order...) {
		out = append(out, p.close(k)...)
	}
	return out
}

// Pending reports how many groups are still open.
func (p *Parser) Pending() int { return len(p.groups) }

func (p *Parser) close(k groupKey) []event.Event {
	g := p.groups[k]
	if g == nil {
		return nil
	}
	delete(p.groups, k)
	for i, ok := range p.order {
		if ok == k {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	if ev, ok := p.build(k, g.records); ok {
		return []event.Event{ev}
	}
	return nil
}

// isSingleRecordType lists user-space (PAM/daemon) record types that form a
// complete event on their own.
func isSingleRecordType(t string) bool {
	switch {
	case strings.HasPrefix(t, "USER_"), strings.HasPrefix(t, "CRED_"), strings.HasPrefix(t, "DAEMON_"):
		return true
	case t == "LOGIN", t == "SERVICE_START", t == "SERVICE_STOP", t == "CONFIG_CHANGE", t == "SYSTEM_BOOT", t == "SYSTEM_SHUTDOWN":
		return true
	}
	return false
}

// build turns a closed group into an event, if the group is one we report.
func (p *Parser) build(k groupKey, recs []Record) (event.Event, bool) {
	if len(recs) == 0 {
		return event.Event{}, false
	}
	var syscall, cwd, proctitle *Record
	var execves []Record
	for i := range recs {
		r := &recs[i]
		switch r.Type {
		case "SYSCALL":
			if syscall == nil {
				syscall = r
			}
		case "EXECVE":
			execves = append(execves, *r)
		case "CWD":
			cwd = r
		case "PROCTITLE":
			proctitle = r
		case "USER_START", "USER_LOGIN":
			return p.buildLogin(*r, event.AuditLogin)
		case "USER_END", "USER_LOGOUT":
			return p.buildLogin(*r, event.AuditLogout)
		}
	}
	exec := len(execves) > 0 || (syscall != nil && isExecve(*syscall))
	if !exec {
		return event.Event{}, false
	}
	ev := event.Event{
		TS:     time.Unix(0, k.ts).UTC(),
		Kind:   event.AuditExecve,
		Source: "auditd",
		Fields: map[string]string{},
	}
	ev.Set("serial", strconv.FormatUint(k.serial, 10))
	if syscall != nil {
		f := syscall.Fields
		ev.PID = atoi(f["pid"])
		ev.Ses = atoi(f["ses"])
		if name := syscall.Enriched["AUID"]; name != "" && name != "unset" {
			ev.User = name
			ev.Set("auid_name", name)
		}
		if name := syscall.Enriched["UID"]; name != "" {
			ev.Set("uid_name", name)
		}
		for _, key := range []string{"exe", "comm", "tty", "uid", "auid", "ppid", "key", "success", "arch", "syscall", "exit"} {
			if v, ok := f[key]; ok {
				switch key {
				case "exe":
					v = capBytes(v, maxNameLen)
				case "comm":
					v = capBytes(v, maxCommLen)
				}
				ev.Set(key, v)
			}
		}
	}
	if cwd != nil {
		ev.Set("cwd", capBytes(cwd.Fields["cwd"], maxNameLen))
	}
	argv, argc := argvFromExecve(execves)
	if len(argv) == 0 && proctitle != nil {
		// No EXECVE record (rule without it or lost record): proctitle is the
		// NUL-joined argv captured at syscall exit.
		if t := proctitle.Fields["proctitle"]; t != "" {
			argv = strings.Split(strings.TrimRight(t, "\x00"), "\x00")
			ev.Set("argv_from", "proctitle")
		}
	}
	if len(argv) > 0 {
		ev.Set("argv0", capBytes(argv[0], maxNameLen))
		ev.Set("cmd", capBytes(joinCapped(argv, maxCmdLen), maxCmdLen))
	}
	if argc == "" {
		argc = strconv.Itoa(len(argv))
	}
	ev.Set("argc", argc)
	p.events.Add(1)
	return ev, true
}

// buildLogin maps a PAM USER_START/USER_LOGIN/USER_END/USER_LOGOUT record from
// sshd into audit.login / audit.logout. Records from other services (cron,
// sudo, su, login) are ignored.
func (p *Parser) buildLogin(r Record, kind event.Kind) (event.Event, bool) {
	if !fromSSHD(r.Fields) {
		return event.Event{}, false
	}
	f := r.Fields
	ev := event.Event{
		TS:     r.TS,
		Kind:   kind,
		Source: "auditd",
		PID:    atoi(f["pid"]),
		Ses:    atoi(f["ses"]),
		Fields: map[string]string{},
	}
	ev.Set("type", r.Type)
	ev.Set("serial", strconv.FormatUint(r.Serial, 10))
	ev.User = f["acct"]
	if ev.User == "" {
		// USER_LOGIN carries id=UID, not acct=. ENRICHED logs resolve it as ID="name".
		ev.User = r.Enriched["ID"]
	}
	if id, ok := f["id"]; ok {
		ev.Set("uid", id)
	}
	if addr := f["addr"]; addr != "" && addr != "?" {
		ev.SrcIP = addr
	}
	for _, key := range []string{"acct", "addr", "hostname", "terminal", "res", "op", "exe", "auid"} {
		if v, ok := f[key]; ok {
			ev.Set(key, v)
		}
	}
	p.events.Add(1)
	return ev, true
}

// fromSSHD reports whether a PAM record was produced by sshd (any OpenSSH
// generation: sshd, sshd-session, sshd-auth) or on the "ssh" PAM terminal.
func fromSSHD(f map[string]string) bool {
	if f["terminal"] == "ssh" {
		return true
	}
	switch path.Base(f["exe"]) {
	case "sshd", "sshd-session", "sshd-auth":
		return true
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// capBytes truncates s to max bytes without splitting a UTF-8 sequence.
func capBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// joinCapped joins argv with spaces but stops once max bytes are reached, so
// a 100k-argument execve does not build a multi-megabyte string only to be
// cut down to 2 KiB.
func joinCapped(argv []string, max int) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		if b.Len()+len(a) > max {
			b.WriteString(a[:max-b.Len()])
			break
		}
		b.WriteString(a)
	}
	return b.String()
}

// flushAllBut closes every open group except the keep most recently opened
// ones, regardless of age. Replay uses it as its clock-free stale sweep.
func (p *Parser) flushAllBut(keep int) []event.Event {
	if len(p.order) <= keep {
		return nil
	}
	stale := append([]groupKey(nil), p.order[:len(p.order)-keep]...)
	var out []event.Event
	for _, k := range stale {
		out = append(out, p.close(k)...)
	}
	return out
}
