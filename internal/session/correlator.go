package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

// Options tunes the Correlator. Zero values take the documented defaults.
type Options struct {
	Window           time.Duration    // scoring window; a track expires Window after its last event (default 15m)
	MaxExecsPerTrack int              // oldest ExecSamples are dropped past this (default 2000)
	ProcTTL          time.Duration    // a ProcSample not refreshed within ProcTTL is trimmed by Expire (default 60s = 3 procfs scans)
	Now              func() time.Time // clock for events without a timestamp (default time.Now)
}

// Correlator joins events from sshd logs, auditd and procfs into Tracks.
//
// It is deliberately single-goroutine: the pipeline owner calls Apply, Expire,
// Snapshot and Restore from one goroutine (the correlator loop), so no locking
// is needed and Tracks returned by Apply may be read until the next call.
type Correlator struct {
	opts Options

	tracks    map[string]*Track   // by Track.ID
	byKey     map[TrackKey]*Track // open track per key
	byPID     map[int]*connRef    // sshd child pid -> connection
	byTuple   map[tuple]*connRef  // (user, ip, port) -> connection
	bySes     map[int]*Track      // audit session id -> track
	byProcPID map[int]*Track      // process pid (procfs) -> track
	userLast  map[string]*Track   // most recently active track per user
	uidUser   map[string]string   // uid -> user, learned from pam_open / proc.seen
}

type tuple struct {
	user string
	ip   string
	port int
}

// connRef binds a Connection to the Track it currently lives on. Track is nil
// for a "pending" connection seen (banner) before the user is known.
type connRef struct {
	conn  *Connection
	track *Track
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
		t = c.authFail(ev, ts)
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
	if t != nil {
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

func (c *Correlator) authFail(ev event.Event, ts time.Time) *Track {
	t := c.recentTrack(ev.User, ev.SrcIP)
	if t == nil {
		t = c.trackFor(TrackKey{User: ev.User, Fingerprint: "-", SrcIP: ev.SrcIP}, ts)
	}
	t.AuthFails++
	return t
}

func (c *Correlator) sessionStart(ev event.Event, ts time.Time) *Track {
	ref := c.ensureConn(ev, ts)
	if ref == nil {
		return nil
	}
	conn := ref.conn
	switch ev.Field("stype") {
	case "command":
		conn.ExecCount++
		if ref.track != nil {
			c.addExec(ref.track, ExecSample{TS: ts, Cmd: ev.Field("cmd"), Ses: conn.Ses, PID: conn.SSHDPID, Origin: "sshlog"})
		}
	case "shell":
		conn.ShellCount++
		setPTY(conn, ts)
	case "subsystem":
		// sftp/scp subsystems say nothing about rhythm; the connection itself is recorded.
	}
	if ev.Field("tty") != "" {
		setPTY(conn, ts)
	}
	return ref.track
}

func (c *Correlator) banner(ev event.Event, ts time.Time) *Track {
	ref := c.ensureConn(ev, ts)
	if ref == nil {
		return nil
	}
	ref.conn.Banner = ev.Field("banner")
	return ref.track
}

func (c *Correlator) sshEnv(ev event.Event, ts time.Time) *Track {
	ref := c.ensureConn(ev, ts)
	if ref == nil {
		return nil
	}
	if ev.Field("name") == "AI_AGENT" && ev.Field("value") != "" {
		ref.conn.DeclaredAgent = ev.Field("value")
		if ref.track != nil {
			ref.track.DeclaredAgent = ev.Field("value")
		}
	}
	return ref.track
}

// pamOpen learns the uid->user mapping (used to attribute auditd execves that
// carry no session id) and touches the connection's track.
func (c *Correlator) pamOpen(ev event.Event) *Track {
	if uid := ev.Field("uid"); uid != "" && ev.User != "" {
		c.uidUser[uid] = ev.User
	}
	ref := c.findConn(ev)
	if ref == nil {
		return nil
	}
	return ref.track
}

func (c *Correlator) disconnect(ev event.Event, ts time.Time) *Track {
	ref := c.findConn(ev)
	if ref == nil {
		return nil
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
	c.addExec(t, ExecSample{TS: ts, Argv0: ev.Field("argv0"), Cmd: ev.Field("cmd"), Ses: sesOf(ev), PID: ev.PID, Origin: "auditd"})
	return t
}

// ---- proc.* / net.* ----------------------------------------------------------

func (c *Correlator) procSeen(ev event.Event, ts time.Time) *Track {
	if uid := ev.Field("uid"); uid != "" && ev.User != "" {
		c.uidUser[uid] = ev.User
	}
	t := c.attributeLocal(ev, ts)
	if t == nil {
		return nil
	}
	ps := ProcSample{
		TS:       ts,
		PID:      ev.PID,
		Comm:     ev.Field("comm"),
		Exe:      ev.Field("exe"),
		Cmd:      ev.Field("cmd"),
		Ses:      sesOf(ev),
		UID:      atoi(ev.Field("uid")),
		Agent:    ev.Field("agent"),
		LastSeen: ts,
	}
	if f := ev.Field("flags"); f != "" {
		for _, x := range strings.Split(f, ",") {
			if x = strings.TrimSpace(x); x != "" {
				ps.Flags = append(ps.Flags, x)
			}
		}
	}
	for k, v := range ev.Fields {
		if name, ok := strings.CutPrefix(k, "env."); ok && name != "" {
			if ps.Env == nil {
				ps.Env = map[string]string{}
			}
			ps.Env[name] = v
		}
	}
	if v := ps.Env["AI_AGENT"]; v != "" {
		t.DeclaredAgent = v
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
	return t
}

func (c *Correlator) netConn(ev event.Event, ts time.Time) *Track {
	_, knownPID := c.byProcPID[ev.PID]
	t := c.trackBySes(ev)
	if t == nil && knownPID {
		t = c.byProcPID[ev.PID]
	}
	if t == nil {
		t = c.attributeLocal(ev, ts)
	}
	if t == nil {
		return nil
	}
	t.NetConns = append(t.NetConns, NetSample{
		TS:         ts,
		Dst:        ev.Field("dst"),
		DstPort:    atoi(ev.Field("dst_port")),
		Host:       ev.Field("host"),
		Agent:      ev.Field("agent"),
		PID:        ev.PID,
		Attributed: sesOf(ev) != 0 || knownPID,
	})
	return t
}

// attributeLocal joins a procfs/netconn event to a track: by audit session,
// then by the most recent track of the same user, else a fresh local track.
func (c *Correlator) attributeLocal(ev event.Event, ts time.Time) *Track {
	if t := c.trackBySes(ev); t != nil {
		return t
	}
	user := c.userOf(ev)
	if user == "" {
		return nil
	}
	if t := c.userLast[user]; t != nil {
		return t
	}
	t := c.trackFor(TrackKey{User: user, Fingerprint: "-", SrcIP: "local"}, ts)
	t.Mode = "local_agent"
	return t
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
	if ref.conn.User != "" && ref.conn.SrcPort != 0 {
		c.byTuple[tuple{ref.conn.User, ref.conn.SrcIP, ref.conn.SrcPort}] = ref
	}
}

func (c *Correlator) unindex(ref *connRef) {
	if r := c.byPID[ref.conn.SSHDPID]; r == ref {
		delete(c.byPID, ref.conn.SSHDPID)
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
		}
	}
	if ref.track != dst {
		dst.Connections = append(dst.Connections, ref.conn)
		ref.track = dst
	}
	if ref.conn.Ses != 0 {
		c.bySes[ref.conn.Ses] = dst
	}
	if ref.conn.DeclaredAgent != "" && dst.DeclaredAgent == "" {
		dst.DeclaredAgent = ref.conn.DeclaredAgent
	}
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
		if p.Agent != "" || len(p.Env) > 0 || len(p.Flags) > 0 {
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
	for _, conn := range t.Connections {
		if ref := c.byPID[conn.SSHDPID]; ref != nil && ref.conn == conn {
			delete(c.byPID, conn.SSHDPID)
		}
		k := tuple{conn.User, conn.SrcIP, conn.SrcPort}
		if ref := c.byTuple[k]; ref != nil && ref.conn == conn {
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
		t.Procs = kept
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
