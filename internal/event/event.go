// Package event defines the single event type that every reader emits and the
// correlator consumes. It is a frozen contract: add Kinds and Field keys, do
// not change existing ones.
package event

import "time"

// Kind names what happened. Readers only emit Kinds listed here.
type Kind string

const (
	// sshd log events (source "sshlog").
	SSHAuthOK       Kind = "ssh.auth_ok"       // Accepted publickey/password. Fields: method, fp, keytype
	SSHAuthFail     Kind = "ssh.auth_fail"     // Failed/Invalid user/Connection closed by authenticating user
	SSHBanner       Kind = "ssh.banner"        // client software version (DEBUG1 only). Fields: banner
	SSHSessionStart Kind = "ssh.session_start" // Starting session: command|shell|subsystem. Fields: stype, tty, chan
	SSHEnv          Kind = "ssh.env"           // an accepted SetEnv (rare, DEBUG). Fields: name, value
	SSHDisconnect   Kind = "ssh.disconnect"    // Disconnected from / Received disconnect
	SSHPAMOpen      Kind = "ssh.pam_open"      // pam_unix(sshd:session): session opened. Fields: uid

	// auditd events (source "auditd").
	AuditLogin  Kind = "audit.login"  // USER_LOGIN/USER_START. Fields: acct, addr, terminal, res
	AuditLogout Kind = "audit.logout" // USER_END/USER_LOGOUT
	AuditExecve Kind = "audit.execve" // Fields: argv0, cmd, exe, comm, cwd, tty, uid, auid, ppid

	// /proc events (source "procfs").
	ProcSeen Kind = "proc.seen" // Fields: comm, exe, argv0, cmd, uid, loginuid, ppid, env.<NAME> for matched vars, flags, agent
	ProcGone Kind = "proc.gone"
	NetConn  Kind = "net.conn" // Fields: dst, dst_port, host, uid, comm, agent

	// Synthetic (replay / simulate).
	Tick Kind = "tick"
)

// Event is one observation from one source. Fields carries kind-specific data;
// keys are documented next to each Kind above. Never re-parse text found in a
// Field as if it were a log line (log-line injection defence).
type Event struct {
	TS      time.Time         `json:"ts"`
	Kind    Kind              `json:"kind"`
	Source  string            `json:"source"` // "sshlog" | "auditd" | "procfs" | "replay"
	User    string            `json:"user,omitempty"`
	SrcIP   string            `json:"src_ip,omitempty"`
	SrcPort int               `json:"src_port,omitempty"`
	PID     int               `json:"pid,omitempty"` // sshd child pid for ssh.*, process pid for proc.*/audit.*
	Ses     int               `json:"ses,omitempty"` // audit session id; 0 = unknown, -1 = unset (4294967295)
	Fields  map[string]string `json:"fields,omitempty"`
}

// Field returns Fields[k] or "".
func (e Event) Field(k string) string {
	if e.Fields == nil {
		return ""
	}
	return e.Fields[k]
}

// Set assigns Fields[k]=v, allocating the map on first use, and returns e for chaining.
func (e *Event) Set(k, v string) *Event {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields[k] = v
	return e
}

// Strong reports whether the event should trigger an immediate re-score
// rather than waiting for the rate-limited evaluation.
func (e Event) Strong() bool {
	switch e.Kind {
	case ProcSeen, SSHEnv, NetConn, SSHBanner:
		return true
	}
	return false
}
