package session

import (
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

var t0 = time.Date(2026, 9, 11, 13, 50, 0, 0, time.UTC)

func at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

func ev(kind event.Kind, ts time.Time, kv ...string) event.Event {
	e := event.Event{TS: ts, Kind: kind, Source: "test"}
	for i := 0; i+1 < len(kv); i += 2 {
		e.Set(kv[i], kv[i+1])
	}
	return e
}

func sshEv(kind event.Kind, ts time.Time, user, ip string, port, pid int, kv ...string) event.Event {
	e := ev(kind, ts, kv...)
	e.Source = "sshlog"
	e.User, e.SrcIP, e.SrcPort, e.PID = user, ip, port, pid
	return e
}

const fp = "SHA256:Qm3kAbCdEf0123456789"

func TestPIDJoinFullSSHLifecycle(t *testing.T) {
	c := New(Options{})
	tr, strong := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "method", "publickey", "fp", fp))
	if tr == nil || strong {
		t.Fatalf("auth_ok: track=%v strong=%v", tr, strong)
	}
	if tr.Key != (TrackKey{"alice", fp, "10.0.0.5"}) {
		t.Fatalf("key = %+v", tr.Key)
	}
	if len(tr.ID) != 15 || tr.ID[:3] != "tr_" {
		t.Fatalf("bad track id %q", tr.ID)
	}
	// Later lines carry only the pid (sshd child), not the tuple.
	tr2, _ := c.Apply(withPID(ev(event.SSHSessionStart, at(1), "stype", "shell", "tty", "pts/3"), 4410))
	if tr2 != tr {
		t.Fatal("session_start by pid did not join the same track")
	}
	conn := tr.Connections[0]
	if !conn.PTY || conn.ShellCount != 1 || conn.PTYOpened.IsZero() || len(conn.ID) != 11 {
		t.Fatalf("conn after shell: %+v", *conn)
	}
	_, strong = c.Apply(withPID(ev(event.SSHBanner, at(1.5), "banner", "SSH-2.0-OpenSSH_9.9"), 4410))
	if !strong || conn.Banner != "SSH-2.0-OpenSSH_9.9" {
		t.Fatalf("banner: strong=%v banner=%q", strong, conn.Banner)
	}
	c.Apply(withPID(ev(event.SSHDisconnect, at(600)), 4410))
	if conn.Closed.IsZero() {
		t.Fatal("disconnect did not close the connection")
	}
	if got := c.byPID[4410]; got != nil {
		t.Fatal("closed connection still indexed by pid")
	}
	if tr.Mode != "remote_agent" {
		t.Fatalf("mode = %q", tr.Mode)
	}
}

func TestTupleJoinWhenPIDDiffers(t *testing.T) {
	// OpenSSH 10 logs auth from sshd-auth (one pid) and the session from
	// sshd-session (another pid); the (user, ip, port) tuple is the join key.
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "bob", "10.0.0.9", 40000, 700, "method", "publickey", "fp", fp))
	tr2, _ := c.Apply(sshEv(event.SSHSessionStart, at(0.2), "bob", "10.0.0.9", 40000, 701, "stype", "command"))
	if tr2 != tr {
		t.Fatal("tuple join failed")
	}
	if len(tr.Connections) != 1 || tr.Connections[0].ExecCount != 1 || len(tr.Execs) != 1 || tr.Execs[0].Origin != "sshlog" {
		t.Fatalf("track after command: %s", tr)
	}
}

func TestBannerBeforeAcceptedIsPendingThenJoined(t *testing.T) {
	// DEBUG1 banner line arrives before Accepted and knows only the pid.
	c := New(Options{})
	tr, _ := c.Apply(withPID(ev(event.SSHBanner, at(0), "banner", "SSH-2.0-paramiko_3.4.0"), 900))
	if tr != nil {
		t.Fatal("banner without user should not create a track")
	}
	if len(c.Tracks()) != 0 {
		t.Fatal("pending connection leaked a track")
	}
	tr, _ = c.Apply(sshEv(event.SSHAuthOK, at(0.5), "svc", "10.1.1.1", 5555, 900, "fp", fp))
	if tr == nil || len(tr.Connections) != 1 || tr.Connections[0].Banner != "SSH-2.0-paramiko_3.4.0" {
		t.Fatalf("banner not carried to the accepted connection: %v", tr)
	}
}

func TestProvisionalConnectionUpgradedOnAccepted(t *testing.T) {
	// VERBOSE "Starting session" seen before Accepted (journal reordering):
	// the provisional "-" track must merge into the fingerprint track.
	c := New(Options{})
	tr1, _ := c.Apply(sshEv(event.SSHSessionStart, at(0), "carol", "10.2.2.2", 6000, 1200, "stype", "command"))
	if tr1 == nil || tr1.Key.Fingerprint != "-" || len(tr1.Execs) != 1 {
		t.Fatalf("provisional: %v", tr1)
	}
	tr2, _ := c.Apply(sshEv(event.SSHAuthOK, at(0.1), "carol", "10.2.2.2", 6000, 1200, "fp", fp))
	if tr2 == tr1 || tr2.Key.Fingerprint != fp {
		t.Fatalf("expected new keyed track, got %v", tr2)
	}
	if len(tr2.Connections) != 1 || len(tr2.Execs) != 1 || tr2.Connections[0].ExecCount != 1 {
		t.Fatalf("exec sample not migrated: %v", tr2)
	}
	if got := c.Tracks(); len(got) != 1 {
		t.Fatalf("empty provisional track not dropped: %d tracks", len(got))
	}
}

func TestControlMasterOneAcceptedManyExecChannels(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "deploy", "10.0.0.7", 42000, 3000, "fp", fp))
	for i := 0; i < 14; i++ {
		got, _ := c.Apply(withPID(ev(event.SSHSessionStart, at(float64(i)*3+1), "stype", "command"), 3000))
		if got != tr {
			t.Fatalf("exec %d joined another track", i)
		}
	}
	if len(tr.Connections) != 1 || tr.ExecChannels() != 14 || len(tr.Execs) != 14 || tr.PTYSessions() != 0 {
		t.Fatalf("controlmaster: %s", tr)
	}
	// A subsystem channel is recorded on the connection but not as an exec.
	c.Apply(withPID(ev(event.SSHSessionStart, at(50), "stype", "subsystem"), 3000))
	if tr.ExecChannels() != 14 {
		t.Fatal("subsystem counted as exec")
	}
}

func TestSesJoinAuditLoginAndExecve(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	login := ev(event.AuditLogin, at(0.3), "acct", "alice", "addr", "10.0.0.5", "res", "success")
	login.PID, login.Ses = 4410, 7
	if got, _ := c.Apply(login); got != tr {
		t.Fatal("audit.login by pid failed")
	}
	if tr.Connections[0].Ses != 7 {
		t.Fatal("ses not recorded on connection")
	}
	ex := ev(event.AuditExecve, at(2), "argv0", "git", "cmd", "git status", "uid", "1000")
	ex.PID, ex.Ses = 5000, 7
	if got, _ := c.Apply(ex); got != tr {
		t.Fatal("execve by ses failed")
	}
	if len(tr.Execs) != 1 || tr.Execs[0].Origin != "auditd" || tr.Execs[0].Argv0 != "git" || tr.Execs[0].Ses != 7 {
		t.Fatalf("exec sample: %+v", tr.Execs)
	}
	// Unknown ses (-1 / unset) but a known uid falls back to the user's latest track.
	pam := sshEv(event.SSHPAMOpen, at(0.2), "alice", "", 0, 4410, "uid", "1000")
	c.Apply(pam)
	ex2 := ev(event.AuditExecve, at(3), "argv0", "ls", "cmd", "ls -la /srv", "uid", "1000")
	ex2.Ses = -1
	if got, _ := c.Apply(ex2); got != tr {
		t.Fatal("execve fallback by uid failed")
	}
	// Completely unknown uid and no user: dropped, not invented.
	ex3 := ev(event.AuditExecve, at(4), "argv0", "cron", "uid", "999")
	if got, _ := c.Apply(ex3); got != nil {
		t.Fatal("unattributable execve created a track")
	}
}

func TestAuditLoginWithoutSSHLogCreatesProvisional(t *testing.T) {
	// auditd only (sshd log unreadable): USER_LOGIN carries acct/addr/pid.
	c := New(Options{})
	login := ev(event.AuditLogin, at(0), "acct", "erin", "addr", "10.3.3.3")
	login.PID, login.Ses = 8000, 12
	tr, _ := c.Apply(login)
	if tr == nil || tr.Key != (TrackKey{"erin", "-", "10.3.3.3"}) || len(tr.Connections) != 1 {
		t.Fatalf("provisional from audit.login: %v", tr)
	}
	ex := ev(event.AuditExecve, at(1), "argv0", "bash", "cmd", "bash -c ls")
	ex.Ses = 12
	if got, _ := c.Apply(ex); got != tr {
		t.Fatal("execve by ses did not join the provisional track")
	}
}

func TestProcSeenAttributionAndLocalTrack(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	login := ev(event.AuditLogin, at(0.3), "acct", "alice", "addr", "10.0.0.5")
	login.PID, login.Ses = 4410, 7
	c.Apply(login)

	// By ses.
	ps := ev(event.ProcSeen, at(30), "comm", "claude", "exe", "/usr/local/bin/claude", "cmd", "claude --dangerously-skip-permissions",
		"uid", "1000", "flags", "--dangerously-skip-permissions", "agent", "claude-code")
	ps.PID, ps.Ses, ps.User, ps.Source = 4411, 7, "alice", "procfs"
	got, strong := c.Apply(ps)
	if got != tr || !strong {
		t.Fatalf("proc.seen by ses: track=%v strong=%v", got, strong)
	}
	if len(tr.Procs) != 1 || tr.Procs[0].Agent != "claude-code" || len(tr.Procs[0].Flags) != 1 || tr.Mode != "local_agent" {
		t.Fatalf("proc sample: %+v mode=%s", tr.Procs, tr.Mode)
	}
	// Re-scan refreshes LastSeen instead of duplicating.
	ps.TS = at(50)
	c.Apply(ps)
	if len(tr.Procs) != 1 || !tr.Procs[0].LastSeen.Equal(at(50)) || !tr.Procs[0].TS.Equal(at(30)) {
		t.Fatalf("rescan: %+v", tr.Procs)
	}
	// Child with env, no ses: by user -> most recent track.
	ch := ev(event.ProcSeen, at(51), "comm", "bash", "cmd", "bash -c git status", "env.CLAUDECODE", "1", "env.AI_AGENT", "claude-code")
	ch.PID, ch.User = 4412, "alice"
	if got, _ := c.Apply(ch); got != tr {
		t.Fatal("proc.seen by user failed")
	}
	if tr.DeclaredAgent != "claude-code" || tr.Procs[1].Env["CLAUDECODE"] != "1" {
		t.Fatalf("env/declared: %+v declared=%q", tr.Procs[1].Env, tr.DeclaredAgent)
	}
	// net.conn by pid of a known process is attributed.
	nc := ev(event.NetConn, at(52), "dst", "160.79.104.10", "dst_port", "443", "host", "api.anthropic.com")
	nc.PID = 4411
	if got, _ := c.Apply(nc); got != tr || len(tr.NetConns) != 1 || !tr.NetConns[0].Attributed || tr.NetConns[0].DstPort != 443 {
		t.Fatalf("net.conn: %+v", tr.NetConns)
	}
	// proc.gone removes the sample.
	gone := ev(event.ProcGone, at(60))
	gone.PID = 4412
	c.Apply(gone)
	if len(tr.Procs) != 1 {
		t.Fatalf("proc.gone: %d procs", len(tr.Procs))
	}
	// A user with no SSH track gets a local track.
	lp := ev(event.ProcSeen, at(70), "comm", "codex", "agent", "codex")
	lp.PID, lp.User = 9000, "svc"
	lt, _ := c.Apply(lp)
	if lt == nil || lt.Key != (TrackKey{"svc", "-", "local"}) || lt.Mode != "local_agent" {
		t.Fatalf("local track: %v", lt)
	}
	// Unattributed net.conn from a user with nothing else: Attributed=false.
	un := ev(event.NetConn, at(71), "dst", "1.2.3.4", "dst_port", "443", "host", "api.openai.com")
	un.PID, un.User = 9999, "svc"
	c.Apply(un)
	if len(lt.NetConns) != 1 || lt.NetConns[0].Attributed {
		t.Fatalf("unattributed net: %+v", lt.NetConns)
	}
}

func TestSSHEnvDeclaresAgent(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	got, strong := c.Apply(withPID(ev(event.SSHEnv, at(1), "name", "AI_AGENT", "value", "claude-code"), 4410))
	if got != tr || !strong || tr.DeclaredAgent != "claude-code" || tr.Connections[0].DeclaredAgent != "claude-code" {
		t.Fatalf("ssh.env: %v declared=%q", got, tr.DeclaredAgent)
	}
	c.Apply(withPID(ev(event.SSHEnv, at(2), "name", "LANG", "value", "C"), 4410))
	if tr.DeclaredAgent != "claude-code" {
		t.Fatal("unrelated env overwrote the declaration")
	}
}

func TestAuthFailCountsOnTrack(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	got, _ := c.Apply(sshEv(event.SSHAuthFail, at(1), "alice", "10.0.0.5", 51300, 4420))
	if got != tr || tr.AuthFails != 1 {
		t.Fatalf("auth_fail: %v fails=%d", got, tr.AuthFails)
	}
	other, _ := c.Apply(sshEv(event.SSHAuthFail, at(2), "root", "10.9.9.9", 1, 4430))
	if other == tr || other.AuthFails != 1 || other.Key.Fingerprint != "-" {
		t.Fatalf("auth_fail new track: %v", other)
	}
}

func TestExpireTrimAndCap(t *testing.T) {
	c := New(Options{Window: 15 * time.Minute, MaxExecsPerTrack: 5})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	for i := 0; i < 8; i++ {
		c.Apply(withPID(ev(event.SSHSessionStart, at(float64(i)), "stype", "command"), 4410))
	}
	if len(tr.Execs) != 5 || !tr.Execs[0].TS.Equal(at(3)) {
		t.Fatalf("cap: %d execs, first at %v", len(tr.Execs), tr.Execs[0].TS)
	}
	ps := ev(event.ProcSeen, at(10), "comm", "claude", "agent", "claude-code")
	ps.PID, ps.User = 77, "alice"
	c.Apply(ps)
	// 20 minutes later a fresh exec keeps the track alive; old execs and the stale proc are trimmed.
	c.Apply(withPID(ev(event.SSHSessionStart, at(1200), "stype", "command"), 4410))
	if gone := c.Expire(at(1201)); len(gone) != 0 {
		t.Fatalf("live track expired: %v", gone)
	}
	if len(tr.Execs) != 1 || len(tr.Procs) != 0 {
		t.Fatalf("trim: execs=%d procs=%d", len(tr.Execs), len(tr.Procs))
	}
	other, _ := c.Apply(sshEv(event.SSHAuthOK, at(1300), "bob", "10.0.0.6", 1, 5))
	gone := c.Expire(at(1200 + 15*60 + 1))
	if len(gone) != 1 || gone[0] != tr || c.Get(tr.ID) != nil || c.Get(other.ID) == nil {
		t.Fatalf("expire: gone=%v", gone)
	}
	if _, ok := c.byPID[4410]; ok {
		t.Fatal("expired track left a pid index behind")
	}
}

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	c := New(Options{})
	tr, _ := c.Apply(sshEv(event.SSHAuthOK, at(0), "alice", "10.0.0.5", 51234, 4410, "fp", fp))
	login := ev(event.AuditLogin, at(0.3), "acct", "alice", "addr", "10.0.0.5")
	login.PID, login.Ses = 4410, 7
	c.Apply(login)
	ps := ev(event.ProcSeen, at(1), "comm", "claude", "env.CLAUDECODE", "1", "flags", "--yolo")
	ps.PID, ps.Ses = 4411, 7
	c.Apply(ps)

	snap := c.Snapshot()
	if len(snap) != 1 || snap[0] == tr || snap[0].Connections[0] == tr.Connections[0] {
		t.Fatal("snapshot is not a deep copy")
	}
	snap[0].Procs[0].Env["X"] = "y"
	if _, leaked := tr.Procs[0].Env["X"]; leaked {
		t.Fatal("snapshot env map shares storage")
	}
	delete(snap[0].Procs[0].Env, "X")

	c2 := New(Options{})
	c2.Restore(snap)
	got := c2.Get(tr.ID)
	if got == nil || got == snap[0] || got.Connections[0].Ses != 7 {
		t.Fatalf("restore: %v", got)
	}
	// Indexes were rebuilt: pid, ses and proc pid joins still work.
	if x, _ := c2.Apply(withPID(ev(event.SSHSessionStart, at(5), "stype", "command"), 4410)); x != got {
		t.Fatal("pid index not restored")
	}
	ex := ev(event.AuditExecve, at(6), "argv0", "ls")
	ex.Ses = 7
	if x, _ := c2.Apply(ex); x != got {
		t.Fatal("ses index not restored")
	}
	g := ev(event.ProcGone, at(7))
	g.PID = 4411
	if x, _ := c2.Apply(g); x != got || len(got.Procs) != 0 {
		t.Fatal("proc pid index not restored")
	}
}

func TestZeroTimestampUsesClock(t *testing.T) {
	now := at(100)
	c := New(Options{Now: func() time.Time { return now }})
	e := sshEv(event.SSHAuthOK, time.Time{}, "alice", "10.0.0.5", 1, 2)
	tr, _ := c.Apply(e)
	if !tr.FirstSeen.Equal(now) {
		t.Fatalf("first seen = %v", tr.FirstSeen)
	}
}

// withPID is a test convenience for lines that only carry the sshd child pid.
func withPID(e event.Event, pid int) event.Event { e.PID = pid; return e }
