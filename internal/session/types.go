// Package session correlates events into Connections and Tracks (the scoring window).
package session

import "time"

// TrackKey identifies a scoring window. Fingerprint is the stable identity
// across ControlMaster, NAT and IP changes; "-" when unknown.
type TrackKey struct {
	User        string `json:"user"`
	Fingerprint string `json:"fingerprint"`
	SrcIP       string `json:"src_ip"`
}

// Connection is one TCP connection to sshd (one sshd child).
type Connection struct {
	ID            string    `json:"id"`
	User          string    `json:"user"`
	SrcIP         string    `json:"src_ip"`
	SrcPort       int       `json:"src_port"`
	SSHDPID       int       `json:"sshd_pid,omitempty"`
	Ses           int       `json:"ses,omitempty"`
	Fingerprint   string    `json:"fingerprint,omitempty"`
	Method        string    `json:"method,omitempty"`
	Banner        string    `json:"banner,omitempty"`
	DeclaredAgent string    `json:"declared_agent,omitempty"`
	Opened        time.Time `json:"opened"`
	Closed        time.Time `json:"closed,omitempty"`
	PTY           bool      `json:"pty"`
	PTYOpened     time.Time `json:"pty_opened,omitempty"`
	ExecCount     int       `json:"exec_count"`
	ShellCount    int       `json:"shell_count"`
}

// ExecSample is one command execution (an SSH exec channel or an auditd execve).
type ExecSample struct {
	TS     time.Time `json:"ts"`
	Argv0  string    `json:"argv0,omitempty"`
	Cmd    string    `json:"cmd,omitempty"` // full text; redaction happens when evidence is built
	Ses    int       `json:"ses,omitempty"`
	PID    int       `json:"pid,omitempty"`
	Origin string    `json:"origin"` // "sshlog" (exec channel) | "auditd"
}

// ProcSample is a live process attributed to the track.
type ProcSample struct {
	TS       time.Time         `json:"ts"`
	PID      int               `json:"pid"`
	Comm     string            `json:"comm"`
	Exe      string            `json:"exe,omitempty"`
	Cmd      string            `json:"cmd,omitempty"`
	Ses      int               `json:"ses,omitempty"`
	UID      int               `json:"uid,omitempty"`
	Env      map[string]string `json:"env,omitempty"` // only rule-listed vars
	Flags    []string          `json:"flags,omitempty"`
	Agent    string            `json:"agent,omitempty"` // rule id if matched
	LastSeen time.Time         `json:"last_seen"`
}

// NetSample is an outbound connection attributed to the track.
type NetSample struct {
	TS         time.Time `json:"ts"`
	Dst        string    `json:"dst"`
	DstPort    int       `json:"dst_port"`
	Host       string    `json:"host,omitempty"`
	Agent      string    `json:"agent,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Attributed bool      `json:"attributed"` // true if joined via ses/pid, false if only uid
}

// Track is the unit the scorer evaluates.
type Track struct {
	ID            string        `json:"id"`
	Key           TrackKey      `json:"key"`
	Connections   []*Connection `json:"connections"`
	Execs         []ExecSample  `json:"execs"`
	Procs         []ProcSample  `json:"procs"`
	NetConns      []NetSample   `json:"net_conns"`
	AuthFails     int           `json:"auth_fails"`
	DeclaredAgent string        `json:"declared_agent,omitempty"`
	Mode          string        `json:"mode"` // local_agent | remote_agent | unknown
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	// Scoring bookkeeping (owned by the dispatcher, persisted in state).
	MaxLevel  string    `json:"max_level,omitempty"`
	LastAlert time.Time `json:"last_alert,omitempty"`
	LastScore int       `json:"last_score"`
	LastEval  time.Time `json:"last_eval,omitempty"`
	Ended     bool      `json:"ended,omitempty"`
}

// Banners returns the distinct client banners seen on the track.
func (t *Track) Banners() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range t.Connections {
		if c.Banner != "" && !seen[c.Banner] {
			seen[c.Banner] = true
			out = append(out, c.Banner)
		}
	}
	return out
}

// ExecChannels counts SSH exec channels (one-command sessions) on the track.
func (t *Track) ExecChannels() int {
	n := 0
	for _, c := range t.Connections {
		n += c.ExecCount
	}
	return n
}

// PTYSessions counts connections that allocated a PTY.
func (t *Track) PTYSessions() int {
	n := 0
	for _, c := range t.Connections {
		if c.PTY {
			n++
		}
	}
	return n
}
