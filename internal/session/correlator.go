package session

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/clean"
	"github.com/whotyped/whotyped/internal/event"
)

// Options tunes the Correlator. Zero values take the documented defaults.
type Options struct {
	Window           time.Duration    // scoring window; a track expires Window after its last event (default 15m)
	MaxExecsPerTrack int              // oldest ExecSamples are dropped past this (default 2000)
	ProcTTL          time.Duration    // a ProcSample not refreshed within ProcTTL is trimmed by Expire (default 60s = 3 procfs scans)
	Now              func() time.Time // clock for events without a timestamp (default time.Now)
	// OnDrop is called with the id of every track the correlator forgets,
	// whether it expired or was a provisional track absorbed by its real
	// one, so the pipeline can release per-track memos (dispatcher dedupe,
	// dirty set). Optional.
	OnDrop func(id string)
}

// maxFailIPs bounds the per-source-IP auth failure counters. Pre-auth
// failures never create tracks (a brute force would otherwise mint thousands
// of them); the counts are kept for future use and evicted least recently
// used.
const maxFailIPs = 1024

// Correlator joins events from sshd logs, auditd and procfs into Tracks.
//
// It is deliberately single-goroutine: the pipeline owner calls Apply, Expire,
// Snapshot and Restore from one goroutine (the correlator loop), so no locking
// is needed and Tracks returned by Apply may be read until the next call.
type Correlator struct {
	opts Options

	tracks    map[string]*Track   // by Track.ID
	byKey     map[TrackKey]*Track // open track per key
	byPID     map[int]*connRef    // sshd child pid (and post-auth user child pid) -> connection
	byTuple   map[tuple]*connRef  // (user, ip, port) -> connection
	bySes     map[int]*Track      // audit session id -> track
	byProcPID map[int]*Track      // process pid (procfs) -> track
	userLast  map[string]*Track   // most recently active track per user
	uidUser   map[string]string   // uid -> user, learned from pam_open / proc.seen

	failIPs   map[string]*list.Element // src ip -> element in failOrder (value *ipFails)
	failOrder *list.List               // least recently used first
}

type ipFails struct {
	ip    string
	count int
}

type tuple struct {
	user string
	ip   string
	port int
}

// connRef binds a Connection to the Track it currently lives on. Track is nil
// for a "pending" connection seen (banner) before the user is known. child is
// the post-auth "User child is on pid N" pid (OpenSSH <= 9.7), indexed so
// lines logged by that pid without a tuple still join the connection.
type connRef struct {
	conn  *Connection
	track *Track
	child int
}

// New returns a Correlator with defaults applied.
func New(opts Options) *Correlator {
	if opts.Window <= 0 {
		opts.Window = 15 * time.Minute
	}
	if opts.MaxExecsPerTrack <= 0 {
		opts.MaxExecsPerTrack = 2000
	}
	if opts.ProcTTL <= 0 {
		opts.ProcTTL = 60 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &Correlator{opts: opts}
	c.reset()
	return c
}

func (c *Correlator) reset() {
	c.tracks = map[string]*Track{}
	c.byKey = map[TrackKey]*Track{}
	c.byPID = map[int]*connRef{}
	c.byTuple = map[tuple]*connRef{}
	c.bySes = map[int]*Track{}
	c.byProcPID = map[int]*Track{}
	c.userLast = map[string]*Track{}
	c.uidUser = map[string]string{}
	c.failIPs = map[string]*list.Element{}
	c.failOrder = list.New()
}

// Apply folds one event into the state and returns the affected track (nil if
// the event could not be attributed) and whether the event is strong, i.e. the
// caller should re-score immediately instead of waiting for the rate limiter.
func (c *Correlator) Apply(ev event.Event) (*Track, bool) {
	ts := ev.TS
	if ts.IsZero() {
		ts = c.opts.Now()
	}
	var t *Track
	switch ev.Kind {
	case event.SSHAuthOK:
		t = c.authOK(ev, ts)
	case event.SSHAuthFail:
		t = c.authFail(ev)
	case event.SSHSessionStart:
		t = c.sessionStart(ev, ts)
	case event.SSHBanner:
		t = c.banner(ev, ts)
	case event.SSHEnv:
		t = c.sshEnv(ev, ts)
	case event.SSHPAMOpen:
		t = c.pamOpen(ev)
	case event.SSHDisconnect:
		t = c.disconnect(ev, ts)
	case event.AuditLogin:
		t = c.auditLogin(ev, ts)
	case event.AuditLogout:
		t = c.trackBySes(ev)
	case event.AuditExecve:
		t = c.auditExecve(ev, ts)
	case event.ProcSeen:
		t = c.procSeen(ev, ts)
	case event.ProcGone:
		t = c.procGone(ev)
	case event.NetConn:
		t = c.netConn(ev, ts)
	}
	// A failed login is not activity of the account: it must neither keep a
	// track alive nor make it the user's most recent one (userLast is what
	// unattributed processes and execves fall back to).
	if t != nil && ev.Kind != event.SSHAuthFail {
		c.touch(t, ts)
	}
	return t, ev.Strong()
}

// ---- ssh.* -----------------------------------------------------------------

func (c *Correlator) authOK(ev event.Event, ts time.Time) *Track {
	ref := c.findConn(ev)
	if ref == nil {
		ref = c.newConn(ev, ts)
	}
	fillConn(ref.conn, ev)
	ref.conn.Method = ev.Field("method")
	if fp := ev.Field("fp"); fp != "" {
		ref.conn.Fingerprint = fp
	}
	c.index(ref)
	key := TrackKey{User: ref.conn.User, Fingerprint: orDash(ref.conn.Fingerprint), SrcIP: ref.conn.SrcIP}
	if ref.track == nil || ref.track.Key != key {
		// The connection was provisional (banner or VERBOSE line before
		// Accepted) and now has its real identity: move it to the keyed track.
		c.moveConn(ref, c.trackFor(key, ts))
	}
	return ref.track
}

// authFail counts a pre-auth failure on an existing track of the same user
// and source (a real session that also fumbled a key) and on the bounded
// per-IP table. It never creates a track: "Invalid user admin from ..." is
// not a session, and a brute force must not cost a Track per attempt.
func (c *Correlator) authFail(ev event.Event) *Track {
	if ev.SrcIP != "" {
		c.countFail(ev.SrcIP)
	}
	if ev.User == "" || ev.Field("invalid_user") == "true" {
		return nil
	}
	t := c.recentTrack(ev.User, ev.SrcIP)
	if t == nil {
		return nil
	}
	t.AuthFails++
	return t
}

func (c *Correlator) countFail(ip string) {
	if el := c.failIPs[ip]; el != nil {
		el.Value.(*ipFails).count++
		c.failOrder.MoveToBack(el)
		return
	}
	for c.failOrder.Len() >= maxFailIPs {
		old := c.failOrder.Front()
		delete(c.failIPs, old.Value.(*ipFails).ip)
		c.failOrder.Remove(old)
	}
	c.failIPs[ip] = c.failOrder.PushBack(&ipFails{ip: ip, count: 1})
}

// AuthFailsByIP returns the pre-auth failures counted for a source IP (0 when
// unknown or evicted). Kept for future brute-force clues; not scored in v0.1.
func (c *Correlator) AuthFailsByIP(ip string) int {
	if el := c.failIPs[ip]; el != nil {
		return el.Value.(*ipFails).count
	}
	return 0
}

// FailIPCount reports how many source IPs the failure table currently holds.
func (c *Correlator) FailIPCount() int { return c.failOrder.Len() }

func (c *Correlator) sessionStart(ev event.Event, ts time.Time) *Track {
	ref := c.ensureConn(ev, ts)
	if ref == nil {
		return nil
	}
	conn := ref.conn
	tty := ev.Field("tty") != ""
	switch ev.Field("stype") {
	case "command", "forced-command":
		// A forced command (authorized_keys command= or sshd ForceCommand)
		// is still one exec channel; sshd logs the command it ran.
		conn.ExecCount++
		if tty {
			// `ssh -tt host cmd`: a terminal on a one-command channel is not
			// an interactive shell and must not cancel pty.none.
			conn.PTYExecCount++
		}
		if ref.track != nil {
			c.addExec(ref.track, ExecSample{TS: ts, Cmd: ev.Field("cmd"), Ses: conn.Ses, PID: conn.SSHDPID, Origin: "sshlog"})
		}
	case "shell":
		conn.ShellCount++
		setPTY(conn, ts)
	case "subsystem":
		// sftp/scp subsystems say nothing about rhythm; the connection itself is recorded.
	}
	return ref.track
}

func (c *Correlator) banner(ev event.Event, ts time.Time) *Track {
	ref := c.ensureConn(ev, ts)
	if ref == nil {
		return nil
	}
	ref.conn.Banner = clean.Text(ev.Field("banner"), clean.MaxName)
	return ref.track
}

func (c *Correlator) sshEnv(ev event.Event, ts time.Time) *Track {
	var ref *connRef
	if ev.Field("via") == "sshrc" {
		// The sshrc hook runs inside an authenticated session, so its
		// connection already exists: never mint a provisional one from a line
		// any local user can write with logger(1). When journald supplies the
		// trusted sender uid and we know whose uid it is, it must be the
		// connection's user.
		ref = c.findConn(ev)
		if ref == nil || ref.conn.User != ev.User {
			return nil
		}
		if uid := ev.Field("uid"); uid != "" {
			if owner, known := c.uidUser[uid]; known && owner != ev.User {
				return nil
			}
		}
	} else {
		ref = c.ensureConn(ev, ts)
	}
	if ref == nil {
		return nil
	}
	if ev.Field("name") == "AI_AGENT" {
		if v, ok := clean.AIAgent(ev.Field("value")); ok {
			ref.conn.DeclaredAgent = v
			if ref.track != nil {
				refreshDeclared(ref.track)
			}
		}
	}
	return ref.track
}

// pamOpen learns the uid->user mapping (used to attribute auditd execves that
// carry no session id), indexes the post-auth child pid when sshd announces
// it, and touches the connection's track.
func (c *Correlator) pamOpen(ev event.Event) *Track {
	if uid := ev.Field("uid"); uid != "" && ev.User != "" {
		c.uidUser[uid] = ev.User
	}
	ref := c.findConn(ev)
	if ref == nil {
		return nil
	}
	if ev.Field("note") == "user_child" {
		if pid := atoi(ev.Field("child_pid")); pid != 0 && ref.child == 0 {
			ref.child = pid
			c.byPID[pid] = ref
		}
	}
	return ref.track
}

// disconnect ends a connection on scope=connection ("Disconnected from",
// "Received disconnect", "Connection closed/reset") or, when the connection
// is still open, on the PAM session close. A scope=channel line ("Close
// session: user ... id N") only ends one channel: with ControlMaster or a
// tool's pooled connection the TCP connection lives on, and closing it here
// would make the next "Starting session" mint a fingerprint-less
// provisional connection on a second track.
func (c *Correlator) disconnect(ev event.Event, ts time.Time) *Track {
	ref := c.findConn(ev)
	if ref == nil {
		return nil
	}
	if ev.Field("scope") == "channel" {
		return ref.track
	}
	ref.conn.Closed = ts
	c.unindex(ref) // pids and ports get reused; never join new lines to a closed connection
	return ref.track
}

// ---- audit.* ---------------------------------------------------------------

func (c *Correlator) auditLogin(ev event.Event, ts time.Time) *Track {
	if ev.User == "" {
		ev.User = ev.Field("acct")
	}
	if ev.SrcIP == "" {
		ev.SrcIP = ev.Field("addr")
	}
	ref := c.findConn(ev)
	if ref == nil {
		ref = c.recentOpenConn(ev.User, ev.SrcIP)
	}
	if ref == nil {
		if ev.User == "" {
			return nil
		}
		ref = c.newConn(ev, ts)
		c.index(ref)
		c.moveConn(ref, c.trackFor(TrackKey{User: ev.User, Fingerprint: "-", SrcIP: ev.SrcIP}, ts))
	}
	if ses := sesOf(ev); ses != 0 {
		ref.conn.Ses = ses
		if ref.track != nil {
			c.bySes[ses] = ref.track
		}
	}
	return ref.track
}

func (c *Correlator) trackBySes(ev event.Event) *Track {
	if ses := sesOf(ev); ses != 0 {
		return c.bySes[ses]
	}
	return nil
}

func (c *Correlator) auditExecve(ev event.Event, ts time.Time) *Track {
	t := c.trackBySes(ev)
	if t == nil {
		t = c.userLast[c.userOf(ev)]
	}
	if t == nil {
		return nil // not an SSH session we know about (cron, console, ...)
	}
	c.addExec(t, ExecSample{TS: ts, Argv0: clean.Text(ev.Field("argv0"), clean.MaxName), Cmd: ev.Field("cmd"), Ses: sesOf(ev), PID: ev.PID, Origin: "auditd"})
	return t
}

// ---- proc.* / net.* ----------------------------------------------------------

func (c *Correlator) procSeen(ev event.Event, ts time.Time) *Track {
	if uid := ev.Field("uid"); uid != "" && ev.User != "" {
		c.uidUser[uid] = ev.User
	}
	t, attributed := c.attributeLocal(ev, ts)
	if t == nil {
		return nil
	}
	ps := ProcSample{
		TS:         ts,
		PID:        ev.PID,
		Comm:       clean.Text(ev.Field("comm"), clean.MaxComm),
		Exe:        clean.Text(ev.Field("exe"), clean.MaxName),
		Cmd:        clean.Text(ev.Field("cmd"), 0),
		Ses:        sesOf(ev),
		UID:        atoi(ev.Field("uid")),
		Agent:      clean.Text(ev.Field("agent"), clean.MaxComm),
		LastSeen:   ts,
		Attributed: attributed,
	}
	if f := ev.Field("flags"); f != "" {
		for _, x := range strings.Split(f, ",") {
			if x = strings.TrimSpace(x); x != "" {
				ps.Flags = append(ps.Flags, clean.Text(x, clean.MaxComm))
			}
		}
	}
	for k, v := range ev.Fields {
		if name, ok := strings.CutPrefix(k, "env."); ok && name != "" {
			if ps.Env == nil {
				ps.Env = map[string]string{}
			}
			if name == "AI_AGENT" {
				// The value is kept (as-is when valid, as the marker when
				// not) so proc.agent_env and the operator still see it;
				// refreshDeclared re-validates before it becomes a claim.
				v, _ = clean.AIAgent(v)
			} else {
				v = clean.Text(v, clean.MaxAIAgent)
			}
			ps.Env[name] = v
		}
	}
	replaced := false
	for i := range t.Procs {
		if t.Procs[i].PID == ps.PID {
			ps.TS = t.Procs[i].TS // keep first-seen
			t.Procs[i] = ps
			replaced = true
			break
		}
	}
	if !replaced {
		t.Procs = append(t.Procs, ps)
	}
	c.byProcPID[ps.PID] = t
	refreshDeclared(t)
	return t
}

func (c *Correlator) procGone(ev event.Event) *Track {
	t := c.byProcPID[ev.PID]
	if t == nil {
		return nil
	}
	delete(c.byProcPID, ev.PID)
	for i := range t.Procs {
		if t.Procs[i].PID == ev.PID {
			t.Procs = append(t.Procs[:i], t.Procs[i+1:]...)
			break
		}
	}
	refreshDeclared(t)
	return t
}

func (c *Correlator) netConn(ev event.Event, ts time.Time) *Track {
	_, knownPID := c.byProcPID[ev.PID]
	t := c.trackBySes(ev)
	if t == nil && knownPID {
		t = c.byProcPID[ev.PID]
	}
	if t == nil {
		t, _ = c.attributeLocal(ev, ts)
	}
	if t == nil {
		return nil
	}
	t.NetConns = append(t.NetConns, NetSample{
		TS:         ts,
		Dst:        ev.Field("dst"),
		DstPort:    atoi(ev.Field("dst_port")),
		Host:       clean.Text(ev.Field("host"), clean.MaxName),
		Agent:      clean.Text(ev.Field("agent"), clean.MaxComm),
		PID:        ev.PID,
		Attributed: sesOf(ev) != 0 || knownPID,
	})
	return t
}

// attributeLocal joins a procfs/netconn event to a track and reports whether
// the join is an attribution (audit session id; parent is the connection's
// sshd child or an attributed process; a fresh local track of its own) or
// merely the user's most recent track. Only attributed processes may declare
// an agent: otherwise `AI_AGENT=x sleep infinity` left in the background
// would label whatever SSH session the same user opens next.
func (c *Correlator) attributeLocal(ev event.Event, ts time.Time) (*Track, bool) {
	if t := c.trackBySes(ev); t != nil {
		return t, true
	}
	if ppid := atoi(ev.Field("ppid")); ppid > 1 {
		if ref := c.byPID[ppid]; ref != nil && ref.track != nil {
			return ref.track, true
		}
		if t := c.byProcPID[ppid]; t != nil {
			for _, p := range t.Procs {
				if p.PID == ppid {
					return t, p.Attributed
				}
			}
			return t, false
		}
	}
	user := c.userOf(ev)
	if user == "" {
		return nil, false
	}
	if t := c.userLast[user]; t != nil {
		return t, false
	}
	t := c.trackFor(TrackKey{User: user, Fingerprint: "-", SrcIP: "local"}, ts)
	t.Mode = "local_agent"
	return t, true
}

// refreshDeclared recomputes Track.DeclaredAgent from what still declares:
// any connection of the track that carried an accepted AI_AGENT SetEnv, else
// any attributed live process with a valid AI_AGENT. When the declaring
// process is gone and nothing else declares, the claim is withdrawn.
func refreshDeclared(t *Track) {
	for _, conn := range t.Connections {
		if conn.DeclaredAgent != "" {
			t.DeclaredAgent = conn.DeclaredAgent
			return
		}
	}
	for _, p := range t.Procs {
		if !p.Attributed || p.Env["AI_AGENT"] == clean.InvalidDeclaration {
			continue
		}
		if v, ok := clean.AIAgent(p.Env["AI_AGENT"]); ok {
			t.DeclaredAgent = v
			return
		}
	}
	t.DeclaredAgent = ""
}

// ---- lookups ---------------------------------------------------------------

// findConn returns the open connection for the event by sshd pid, then tuple.
func (c *Correlator) findConn(ev event.Event) *connRef {
	if ev.PID != 0 {
		if ref := c.byPID[ev.PID]; ref != nil {
			return ref
		}
	}
	if ev.User != "" && ev.SrcPort != 0 {
		if ref := c.byTuple[tuple{ev.User, ev.SrcIP, ev.SrcPort}]; ref != nil {
			return ref
		}
	}
	return nil
}

// ensureConn is findConn plus creation of a provisional connection when a
// line arrives before (or without) the Accepted line. Returns nil only when
// nothing identifies the connection at all.
func (c *Correlator) ensureConn(ev event.Event, ts time.Time) *connRef {
	if ref := c.findConn(ev); ref != nil {
		if ref.conn.User == "" && ev.User != "" {
			fillConn(ref.conn, ev)
			c.index(ref)
			c.moveConn(ref, c.trackFor(TrackKey{User: ev.User, Fingerprint: "-", SrcIP: ev.SrcIP}, ts))
		}
		return ref
	}
	if ev.PID == 0 && (ev.User == "" || ev.SrcPort == 0) {
		return nil
	}
	ref := c.newConn(ev, ts)
	c.index(ref)
	if ev.User != "" {
		c.moveConn(ref, c.trackFor(TrackKey{User: ev.User, Fingerprint: "-", SrcIP: ev.SrcIP}, ts))
	}
	return ref
}

func (c *Correlator) newConn(ev event.Event, ts time.Time) *connRef {
	conn := &Connection{Opened: ts}
	fillConn(conn, ev)
	conn.ID = "cn_" + shortHash(8, conn.User, conn.SrcIP, strconv.Itoa(conn.SrcPort), strconv.Itoa(conn.SSHDPID), strconv.FormatInt(ts.UnixNano(), 10))
	return &connRef{conn: conn}
}

func fillConn(conn *Connection, ev event.Event) {
	if ev.User != "" {
		conn.User = ev.User
	}
	if ev.SrcIP != "" {
		conn.SrcIP = ev.SrcIP
	}
	if ev.SrcPort != 0 {
		conn.SrcPort = ev.SrcPort
	}
	if ev.PID != 0 && conn.SSHDPID == 0 {
		conn.SSHDPID = ev.PID
	}
}

func (c *Correlator) index(ref *connRef) {
	if ref.conn.SSHDPID != 0 {
		c.byPID[ref.conn.SSHDPID] = ref
	}
	if ref.child != 0 {
		c.byPID[ref.child] = ref
	}
	if ref.conn.User != "" && ref.conn.SrcPort != 0 {
		c.byTuple[tuple{ref.conn.User, ref.conn.SrcIP, ref.conn.SrcPort}] = ref
	}
}

func (c *Correlator) unindex(ref *connRef) {
	for _, pid := range []int{ref.conn.SSHDPID, ref.child} {
		if r := c.byPID[pid]; pid != 0 && r == ref {
			delete(c.byPID, pid)
		}
	}
	k := tuple{ref.conn.User, ref.conn.SrcIP, ref.conn.SrcPort}
	if r := c.byTuple[k]; r == ref {
		delete(c.byTuple, k)
	}
}

// moveConn attaches the connection to dst, migrating its sshlog exec samples
// from the previous (provisional) track and deleting that track if empty.
func (c *Correlator) moveConn(ref *connRef, dst *Track) {
	if src := ref.track; src != nil && src != dst {
		for i, x := range src.Connections {
			if x == ref.conn {
				src.Connections = append(src.Connections[:i], src.Connections[i+1:]...)
				break
			}
		}
		kept := src.Execs[:0]
		for _, e := range src.Execs {
			if e.Origin == "sshlog" && e.PID == ref.conn.SSHDPID && ref.conn.SSHDPID != 0 {
				c.addExec(dst, e)
			} else {
				kept = append(kept, e)
			}
		}
		src.Execs = kept
		if len(src.Connections) == 0 && len(src.Execs) == 0 && len(src.Procs) == 0 && len(src.NetConns) == 0 {
			c.drop(src)
		} else {
			refreshDeclared(src)
		}
	}
	if ref.track != dst {
		dst.Connections = append(dst.Connections, ref.conn)
		ref.track = dst
	}
	if ref.conn.Ses != 0 {
		c.bySes[ref.conn.Ses] = dst
	}
	refreshDeclared(dst)
}

func (c *Correlator) trackFor(key TrackKey, ts time.Time) *Track {
	if t := c.byKey[key]; t != nil {
		return t
	}
	t := &Track{Key: key, FirstSeen: ts, LastSeen: ts, Mode: "unknown"}
	t.ID = "tr_" + shortHash(12, key.User, key.Fingerprint, key.SrcIP, strconv.FormatInt(ts.Unix(), 10))
	for c.tracks[t.ID] != nil { // same key twice within one second: disambiguate
		t.ID = "tr_" + shortHash(12, t.ID)
	}
	c.tracks[t.ID] = t
	c.byKey[key] = t
	return t
}

// recentTrack is the most recently active track for user (and ip if given).
func (c *Correlator) recentTrack(user, ip string) *Track {
	var best *Track
	for _, t := range c.tracks {
		if t.Key.User != user || (ip != "" && t.Key.SrcIP != ip) {
			continue
		}
		if best == nil || t.LastSeen.After(best.LastSeen) {
			best = t
		}
	}
	return best
}

func (c *Correlator) recentOpenConn(user, ip string) *connRef {
	var best *connRef
	for _, ref := range c.byTuple {
		if ref.conn.User != user || (ip != "" && ref.conn.SrcIP != ip) {
			continue
		}
		if best == nil || ref.conn.Opened.After(best.conn.Opened) {
			best = ref
		}
	}
	return best
}

func (c *Correlator) userOf(ev event.Event) string {
	if ev.User != "" {
		return ev.User
	}
	return c.uidUser[ev.Field("uid")]
}

// ---- track maintenance -----------------------------------------------------

func (c *Correlator) addExec(t *Track, s ExecSample) {
	if max := c.opts.MaxExecsPerTrack; len(t.Execs) >= max {
		n := copy(t.Execs, t.Execs[len(t.Execs)-max+1:])
		t.Execs = t.Execs[:n]
	}
	t.Execs = append(t.Execs, s)
}

func (c *Correlator) touch(t *Track, ts time.Time) {
	if t.FirstSeen.IsZero() || ts.Before(t.FirstSeen) {
		t.FirstSeen = ts
	}
	if ts.After(t.LastSeen) {
		t.LastSeen = ts
	}
	if cur := c.userLast[t.Key.User]; cur == nil || !cur.LastSeen.After(t.LastSeen) {
		c.userLast[t.Key.User] = t
	}
	t.Mode = modeOf(t)
}

// modeOf derives the threat shape: a process on the box that looks like an
// agent means local_agent; anything driven only through exec channels or
// connections is remote_agent; otherwise unknown.
func modeOf(t *Track) string {
	for _, p := range t.Procs {
		if p.Agent != "" || len(p.Flags) > 0 || hasAgentEnv(p) {
			return "local_agent"
		}
	}
	if t.Key.SrcIP == "local" && len(t.Connections) == 0 {
		return "local_agent"
	}
	if len(t.Connections) > 0 || len(t.Execs) > 0 {
		return "remote_agent"
	}
	return "unknown"
}

func (c *Correlator) drop(t *Track) {
	delete(c.tracks, t.ID)
	if c.byKey[t.Key] == t {
		delete(c.byKey, t.Key)
	}
	for pid, ref := range c.byPID {
		if ref.track == t {
			delete(c.byPID, pid)
		}
	}
	for k, ref := range c.byTuple {
		if ref.track == t {
			delete(c.byTuple, k)
		}
	}
	for ses, x := range c.bySes {
		if x == t {
			delete(c.bySes, ses)
		}
	}
	for pid, x := range c.byProcPID {
		if x == t {
			delete(c.byProcPID, pid)
		}
	}
	if c.userLast[t.Key.User] == t {
		delete(c.userLast, t.Key.User)
	}
	if c.opts.OnDrop != nil {
		c.opts.OnDrop(t.ID)
	}
}

// Expire removes and returns tracks idle for longer than Window, and trims
// samples older than the window (procs older than ProcTTL) from live tracks.
func (c *Correlator) Expire(now time.Time) []*Track {
	var gone []*Track
	for _, t := range c.tracks {
		if now.Sub(t.LastSeen) > c.opts.Window {
			gone = append(gone, t)
			continue
		}
		cut := now.Add(-c.opts.Window)
		t.Execs = trimExecs(t.Execs, cut)
		t.NetConns = trimNet(t.NetConns, cut)
		procCut := now.Add(-c.opts.ProcTTL)
		kept := t.Procs[:0]
		for _, p := range t.Procs {
			if !p.LastSeen.Before(procCut) {
				kept = append(kept, p)
			} else {
				delete(c.byProcPID, p.PID)
			}
		}
		if len(kept) != len(t.Procs) {
			t.Procs = kept
			refreshDeclared(t)
		}
	}
	for _, t := range gone {
		c.drop(t)
	}
	sortTracks(gone)
	return gone
}

func trimExecs(in []ExecSample, cut time.Time) []ExecSample {
	i := 0
	for i < len(in) && in[i].TS.Before(cut) {
		i++
	}
	if i == 0 {
		return in
	}
	return append(in[:0], in[i:]...)
}

func trimNet(in []NetSample, cut time.Time) []NetSample {
	kept := in[:0]
	for _, n := range in {
		if !n.TS.Before(cut) {
			kept = append(kept, n)
		}
	}
	return kept
}

// Tracks returns the live tracks ordered by FirstSeen.
func (c *Correlator) Tracks() []*Track {
	out := make([]*Track, 0, len(c.tracks))
	for _, t := range c.tracks {
		out = append(out, t)
	}
	sortTracks(out)
	return out
}

// Get returns the live track with the given ID, or nil.
func (c *Correlator) Get(id string) *Track { return c.tracks[id] }

// Snapshot returns deep copies of the live tracks for persistence.
func (c *Correlator) Snapshot() []*Track {
	out := make([]*Track, 0, len(c.tracks))
	for _, t := range c.tracks {
		out = append(out, cloneTrack(t))
	}
	sortTracks(out)
	return out
}

// Restore replaces all state with the given tracks (deep-copied) and rebuilds
// the join indexes from them.
func (c *Correlator) Restore(tracks []*Track) {
	c.reset()
	for _, src := range tracks {
		t := cloneTrack(src)
		c.tracks[t.ID] = t
		c.byKey[t.Key] = t
		for _, conn := range t.Connections {
			ref := &connRef{conn: conn, track: t}
			if conn.Closed.IsZero() {
				c.index(ref)
			}
			if conn.Ses != 0 {
				c.bySes[conn.Ses] = t
			}
		}
		for _, p := range t.Procs {
			c.byProcPID[p.PID] = t
			if p.Ses != 0 {
				c.bySes[p.Ses] = t
			}
		}
		if cur := c.userLast[t.Key.User]; cur == nil || t.LastSeen.After(cur.LastSeen) {
			c.userLast[t.Key.User] = t
		}
	}
}

func cloneTrack(t *Track) *Track {
	cp := *t
	cp.Connections = make([]*Connection, len(t.Connections))
	for i, conn := range t.Connections {
		x := *conn
		cp.Connections[i] = &x
	}
	cp.Execs = append([]ExecSample(nil), t.Execs...)
	cp.NetConns = append([]NetSample(nil), t.NetConns...)
	cp.Procs = make([]ProcSample, len(t.Procs))
	for i, p := range t.Procs {
		q := p
		q.Flags = append([]string(nil), p.Flags...)
		if p.Env != nil {
			q.Env = make(map[string]string, len(p.Env))
			for k, v := range p.Env {
				q.Env[k] = v
			}
		}
		cp.Procs[i] = q
	}
	return &cp
}

func sortTracks(ts []*Track) {
	sort.Slice(ts, func(i, j int) bool {
		if !ts[i].FirstSeen.Equal(ts[j].FirstSeen) {
			return ts[i].FirstSeen.Before(ts[j].FirstSeen)
		}
		return ts[i].ID < ts[j].ID
	})
}

// ---- small helpers -----------------------------------------------------------

func setPTY(conn *Connection, ts time.Time) {
	conn.PTY = true
	if conn.PTYOpened.IsZero() {
		conn.PTYOpened = ts
	}
}

// sesOf normalises the audit session id: -1 (unset) and 0 both mean unknown.
func sesOf(ev event.Event) int {
	if ev.Ses <= 0 {
		return 0
	}
	return ev.Ses
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func shortHash(n int, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:n]
}

// String is a compact debug form.
func (t *Track) String() string {
	return fmt.Sprintf("%s %s@%s fp=%s conns=%d execs=%d procs=%d net=%d mode=%s",
		t.ID, t.Key.User, t.Key.SrcIP, t.Key.Fingerprint, len(t.Connections), len(t.Execs), len(t.Procs), len(t.NetConns), t.Mode)
}

// hasAgentEnv reports whether a process carries agent environment evidence.
// Rule-listed markers such as CLAUDECODE count wherever the process was
// placed. AI_AGENT alone counts only for an attributed process: a background
// process that merely exports AI_AGENT (possibly to spoof "human") must not
// turn a user's SSH track into a local-agent track.
func hasAgentEnv(p ProcSample) bool {
	for k := range p.Env {
		if k != "AI_AGENT" {
			return true
		}
	}
	return p.Attributed && p.Env["AI_AGENT"] != ""
}
