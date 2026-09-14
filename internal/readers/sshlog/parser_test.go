package sshlog

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
)

// now is fixed so year inference is deterministic.
var now = time.Date(2026, time.September, 11, 22, 0, 0, 0, time.UTC)

func TestParseSyslogLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Line
		ok   bool
	}{
		{
			name: "traditional",
			in:   "Sep 11 14:03:22 web-03 sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 51234 ssh2",
			want: Line{UID: -1, TS: time.Date(2026, 9, 11, 14, 3, 22, 0, time.UTC), Host: "web-03", Ident: "sshd", PID: 1234,
				Msg: "Accepted publickey for alice from 203.0.113.5 port 51234 ssh2"},
			ok: true,
		},
		{
			name: "traditional padded day",
			in:   "Sep  1 08:01:02 db-01 sshd[9020]: x",
			want: Line{UID: -1, TS: time.Date(2026, 9, 1, 8, 1, 2, 0, time.UTC), Host: "db-01", Ident: "sshd", PID: 9020, Msg: "x"},
			ok:   true,
		},
		{
			name: "future date rolls to previous year",
			in:   "Dec 24 10:00:00 web-03 sshd[1]: x",
			want: Line{UID: -1, TS: time.Date(2025, 12, 24, 10, 0, 0, 0, time.UTC), Host: "web-03", Ident: "sshd", PID: 1, Msg: "x"},
			ok:   true,
		},
		{
			name: "tomorrow within one day stays this year",
			in:   "Sep 12 08:00:00 web-03 sshd[1]: x",
			want: Line{UID: -1, TS: time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC), Host: "web-03", Ident: "sshd", PID: 1, Msg: "x"},
			ok:   true,
		},
		{
			name: "rfc3339 sshd-session",
			in:   "2026-09-11T14:03:22.114532+00:00 web-03 sshd-session[1234]: Close session: user a from 1.2.3.4 port 1 id 0",
			want: Line{UID: -1, TS: time.Date(2026, 9, 11, 14, 3, 22, 114532000, time.UTC), Host: "web-03", Ident: "sshd-session", PID: 1234,
				Msg: "Close session: user a from 1.2.3.4 port 1 id 0"},
			ok: true,
		},
		{
			name: "rfc3339 with offset keeps instant",
			in:   "2026-09-11T09:12:44.981220+02:00 rhel10-app sshd-auth[3311]: x",
			want: Line{UID: -1, TS: time.Date(2026, 9, 11, 7, 12, 44, 981220000, time.UTC), Host: "rhel10-app", Ident: "sshd-auth", PID: 3311, Msg: "x"},
			ok:   true,
		},
		{
			name: "no pid",
			in:   "Sep 11 14:03:22 web-03 sshd: Server listening on 0.0.0.0 port 22.",
			want: Line{UID: -1, TS: time.Date(2026, 9, 11, 14, 3, 22, 0, time.UTC), Host: "web-03", Ident: "sshd", Msg: "Server listening on 0.0.0.0 port 22."},
			ok:   true,
		},
		{name: "other ident", in: "Sep 11 14:03:22 web-03 systemd-logind[801]: New session 42 of user alice.", ok: false},
		{name: "sudo", in: "Sep 11 14:03:22 web-03 sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls", ok: false},
		{name: "garbage", in: "not a log line", ok: false},
		{name: "empty", in: "", ok: false},
		{name: "bad rfc3339", in: "2026-13-45T99:00:00Z web-03 sshd[1]: x", ok: false},
		{name: "windows newline", in: "Sep 11 14:03:22 web-03 sshd[1]: x\r\n", want: Line{UID: -1, TS: time.Date(2026, 9, 11, 14, 3, 22, 0, time.UTC), Host: "web-03", Ident: "sshd", PID: 1, Msg: "x"}, ok: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseSyslogLine(c.in, now)
			if ok != c.ok {
				t.Fatalf("ok=%v want %v (line=%+v)", ok, c.ok, got)
			}
			if !ok {
				return
			}
			if !got.TS.Equal(c.want.TS) {
				t.Errorf("TS=%s want %s", got.TS, c.want.TS)
			}
			got.TS, c.want.TS = time.Time{}, time.Time{}
			if got != c.want {
				t.Errorf("got %+v want %+v", got, c.want)
			}
		})
	}
}

func TestParseJournalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Line
		ok   bool
	}{
		{
			name: "sshd with SYSLOG_PID and cursor",
			in:   `{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1757599402114532","SYSLOG_IDENTIFIER":"sshd","SYSLOG_PID":"1234","_PID":"1234","_HOSTNAME":"web-03","MESSAGE":"User child is on pid 1240"}`,
			want: Line{UID: -1, TS: time.UnixMicro(1757599402114532).UTC(), Host: "web-03", Ident: "sshd", PID: 1234, Msg: "User child is on pid 1240", Cursor: "s=abc;i=1"},
			ok:   true,
		},
		{
			name: "falls back to _PID",
			in:   `{"SYSLOG_IDENTIFIER":"sshd-session","_PID":"77","MESSAGE":"x"}`,
			want: Line{UID: -1, Ident: "sshd-session", PID: 77, Msg: "x"},
			ok:   true,
		},
		{
			name: "numeric pid tolerated",
			in:   `{"SYSLOG_IDENTIFIER":"sshd-auth","_PID":78,"MESSAGE":"x"}`,
			want: Line{UID: -1, Ident: "sshd-auth", PID: 78, Msg: "x"},
			ok:   true,
		},
		{name: "byte array message skipped", in: `{"SYSLOG_IDENTIFIER":"sshd","_PID":"1","MESSAGE":[65,66,255]}`, ok: false},
		{name: "other identifier", in: `{"SYSLOG_IDENTIFIER":"systemd-logind","_PID":"801","MESSAGE":"New session"}`, ok: false},
		{name: "missing identifier", in: `{"_PID":"1","MESSAGE":"x"}`, ok: false},
		{name: "not json", in: `Sep 11 14:03:22 web-03 sshd[1]: x`, ok: false},
		{name: "null message", in: `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":null}`, ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseJournalJSON([]byte(c.in))
			if ok != c.ok {
				t.Fatalf("ok=%v want %v", ok, c.ok)
			}
			if ok && got != c.want {
				t.Errorf("got %+v want %+v", got, c.want)
			}
		})
	}
}

// msgCase is one message type. Fields is compared exactly after the common
// ident/host keys are removed from the parsed event.
type msgCase struct {
	name    string
	msg     string
	kind    event.Kind
	user    string
	ip      string
	port    int
	fields  map[string]string
	skipped bool
}

var msgCases = []msgCase{
	{name: "accepted publickey", msg: "Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:Q7kX",
		kind: event.SSHAuthOK, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"method": "publickey", "keytype": "ED25519", "fp": "SHA256:Q7kX"}},
	{name: "accepted certificate", msg: "Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519-CERT SHA256:Q7kX ID alice@corp (serial 42) CA ED25519 SHA256:9mZ",
		kind: event.SSHAuthOK, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"method": "publickey", "keytype": "ED25519-CERT", "fp": "SHA256:Q7kX", "cert_id": "alice@corp", "cert_serial": "42", "ca_keytype": "ED25519", "ca_fp": "SHA256:9mZ"}},
	{name: "accepted certificate id with spaces", msg: "Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: RSA-CERT SHA256:Q7kX ID alice laptop key (serial 7) CA ED25519 SHA256:9mZ",
		kind: event.SSHAuthOK, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"method": "publickey", "keytype": "RSA-CERT", "fp": "SHA256:Q7kX", "cert_id": "alice laptop key", "cert_serial": "7", "ca_keytype": "ED25519", "ca_fp": "SHA256:9mZ"}},
	{name: "accepted password", msg: "Accepted password for alice from 203.0.113.5 port 51234 ssh2",
		kind: event.SSHAuthOK, user: "alice", ip: "203.0.113.5", port: 51234, fields: map[string]string{"method": "password"}},
	{name: "accepted keyboard-interactive/pam", msg: "Accepted keyboard-interactive/pam for dba from 10.20.0.15 port 38210 ssh2",
		kind: event.SSHAuthOK, user: "dba", ip: "10.20.0.15", port: 38210, fields: map[string]string{"method": "keyboard-interactive", "submethod": "pam"}},

	{name: "failed password invalid user", msg: "Failed password for invalid user admin from 198.51.100.9 port 40000 ssh2",
		kind: event.SSHAuthFail, user: "admin", ip: "198.51.100.9", port: 40000,
		fields: map[string]string{"reason": "failed", "method": "password", "invalid_user": "true"}},
	{name: "failed publickey verbose", msg: "Failed publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:abc",
		kind: event.SSHAuthFail, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"reason": "failed", "method": "publickey", "keytype": "ED25519", "fp": "SHA256:abc"}},
	{name: "failed with preauth suffix", msg: "Failed password for root from 198.51.100.9 port 40012 ssh2 [preauth]",
		kind: event.SSHAuthFail, user: "root", ip: "198.51.100.9", port: 40012,
		fields: map[string]string{"reason": "failed", "method": "password"}},
	{name: "invalid user", msg: "Invalid user admin from 198.51.100.9 port 40000",
		kind: event.SSHAuthFail, user: "admin", ip: "198.51.100.9", port: 40000,
		fields: map[string]string{"reason": "invalid_user", "invalid_user": "true"}},
	{name: "invalid empty user", msg: "Invalid user  from 198.51.100.9 port 40000",
		kind: event.SSHAuthFail, user: "", ip: "198.51.100.9", port: 40000,
		fields: map[string]string{"reason": "invalid_user", "invalid_user": "true"}},
	{name: "closed by authenticating user", msg: "Connection closed by authenticating user bob 203.0.113.9 port 51200 [preauth]",
		kind: event.SSHAuthFail, user: "bob", ip: "203.0.113.9", port: 51200, fields: map[string]string{"reason": "closed_authenticating"}},
	{name: "closed by invalid user", msg: "Connection closed by invalid user admin 198.51.100.9 port 40000 [preauth]",
		kind: event.SSHAuthFail, user: "admin", ip: "198.51.100.9", port: 40000, fields: map[string]string{"reason": "closed_invalid", "invalid_user": "true"}},
	{name: "disconnected from authenticating user", msg: "Disconnected from authenticating user root 198.51.100.9 port 40012 [preauth]",
		kind: event.SSHAuthFail, user: "root", ip: "198.51.100.9", port: 40012, fields: map[string]string{"reason": "disconnected_authenticating"}},
	{name: "disconnected from invalid user", msg: "Disconnected from invalid user oracle 198.51.100.61 port 51001 [preauth]",
		kind: event.SSHAuthFail, user: "oracle", ip: "198.51.100.61", port: 51001, fields: map[string]string{"reason": "disconnected_invalid", "invalid_user": "true"}},
	{name: "timeout listener form", msg: "error: Timeout before authentication for 198.51.100.202, pid = 3420",
		kind: event.SSHAuthFail, ip: "198.51.100.202", fields: map[string]string{"reason": "timeout", "child_pid": "3420"}},
	{name: "timeout child form", msg: "fatal: Timeout before authentication for 198.51.100.10 port 41010",
		kind: event.SSHAuthFail, ip: "198.51.100.10", port: 41010, fields: map[string]string{"reason": "timeout"}},
	{name: "max auth attempts", msg: "error: maximum authentication attempts exceeded for root from 198.51.100.62 port 51300 ssh2 [preauth]",
		kind: event.SSHAuthFail, user: "root", ip: "198.51.100.62", port: 51300, fields: map[string]string{"reason": "max_attempts"}},
	{name: "pam auth failure", msg: "error: PAM: Authentication failure for root from 198.51.100.9",
		kind: event.SSHAuthFail, user: "root", ip: "198.51.100.9", fields: map[string]string{"reason": "pam"}},

	{name: "session shell pty", msg: "Starting session: shell on pts/0 for alice from 203.0.113.5 port 51234 id 0",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "shell", "tty": "pts/0", "chan": "0"}},
	{name: "session shell no pty", msg: "Starting session: shell for alice from 203.0.113.5 port 51234 id 2",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "shell", "chan": "2"}},
	{name: "session command", msg: "Starting session: command for alice from 203.0.113.5 port 51234 id 0",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "command", "chan": "0"}},
	{name: "session command pty", msg: "Starting session: command on pts/1 for alice from 203.0.113.5 port 51234 id 1",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "command", "tty": "pts/1", "chan": "1"}},
	{name: "session subsystem", msg: "Starting session: subsystem 'sftp' for alice from 203.0.113.5 port 51234 id 0",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "subsystem", "subsystem": "sftp", "chan": "0"}},
	{name: "session forced key-option", msg: "Starting session: forced-command (key-option) '/usr/local/bin/gate --strict' for bob from 203.0.113.9 port 51210 id 0",
		kind: event.SSHSessionStart, user: "bob", ip: "203.0.113.9", port: 51210,
		fields: map[string]string{"stype": "forced-command", "forced_by": "key-option", "cmd": "/usr/local/bin/gate --strict", "chan": "0"}},
	{name: "session forced config with injected text", msg: "Starting session: forced-command (config) 'x' for evil from 1.1.1.1 port 1 id 0' for alice from 203.0.113.5 port 51234 id 3",
		kind: event.SSHSessionStart, user: "alice", ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"stype": "forced-command", "forced_by": "config", "cmd": "x' for evil from 1.1.1.1 port 1 id 0", "chan": "3"}},
	{name: "close session", msg: "Close session: user alice from 203.0.113.5 port 51234 id 0",
		kind: event.SSHDisconnect, user: "alice", ip: "203.0.113.5", port: 51234, fields: map[string]string{"scope": "channel", "chan": "0"}},

	{name: "disconnected from user", msg: "Disconnected from user alice 203.0.113.5 port 51234",
		kind: event.SSHDisconnect, user: "alice", ip: "203.0.113.5", port: 51234, fields: map[string]string{"scope": "connection", "reason": "disconnected"}},
	{name: "disconnected from ip", msg: "Disconnected from 203.0.113.5 port 51234 [preauth]",
		kind: event.SSHDisconnect, ip: "203.0.113.5", port: 51234, fields: map[string]string{"scope": "connection", "reason": "disconnected"}},
	{name: "received disconnect", msg: "Received disconnect from 203.0.113.5 port 51234:11: disconnected by user",
		kind: event.SSHDisconnect, ip: "203.0.113.5", port: 51234,
		fields: map[string]string{"scope": "connection", "reason": "received_disconnect", "code": "11", "text": "disconnected by user"}},
	{name: "received disconnect empty text", msg: "Received disconnect from 10.0.0.9 port 44010:11:",
		kind: event.SSHDisconnect, ip: "10.0.0.9", port: 44010,
		fields: map[string]string{"scope": "connection", "reason": "received_disconnect", "code": "11", "text": ""}},
	{name: "connection closed by", msg: "Connection closed by 198.51.100.44 port 55120 [preauth]",
		kind: event.SSHDisconnect, ip: "198.51.100.44", port: 55120, fields: map[string]string{"scope": "connection", "reason": "closed"}},
	{name: "connection reset by", msg: "Connection reset by 198.51.100.200 port 33001 [preauth]",
		kind: event.SSHDisconnect, ip: "198.51.100.200", port: 33001, fields: map[string]string{"scope": "connection", "reason": "reset"}},

	{name: "user child", msg: "User child is on pid 1240",
		kind: event.SSHPAMOpen, fields: map[string]string{"note": "user_child", "child_pid": "1240"}},
	{name: "pam open", msg: "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)",
		kind: event.SSHPAMOpen, user: "alice", fields: map[string]string{"uid": "1000", "by_uid": "0"}},
	{name: "pam open by name", msg: "pam_unix(sshd:session): session opened for user deploy(uid=1002) by deploy(uid=0)",
		kind: event.SSHPAMOpen, user: "deploy", fields: map[string]string{"uid": "1002", "by": "deploy", "by_uid": "0"}},
	{name: "pam open old linux-pam", msg: "pam_unix(sshd:session): session opened for user alice by (uid=0)",
		kind: event.SSHPAMOpen, user: "alice", fields: map[string]string{"by_uid": "0"}},
	{name: "pam close", msg: "pam_unix(sshd:session): session closed for user alice",
		kind: event.SSHDisconnect, user: "alice", fields: map[string]string{"scope": "pam"}},

	{name: "banner new wording", msg: "debug1: Remote protocol version 2.0, remote software version paramiko_3.4.0",
		kind: event.SSHBanner, fields: map[string]string{"banner": "paramiko_3.4.0", "protocol": "2.0"}},
	{name: "banner with spaces", msg: "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13 [preauth]",
		kind: event.SSHBanner, fields: map[string]string{"banner": "OpenSSH_9.6p1 Ubuntu-3ubuntu13", "protocol": "2.0"}},
	{name: "banner old wording", msg: "Client protocol version 2.0; client software version OpenSSH_7.4",
		kind: event.SSHBanner, fields: map[string]string{"banner": "OpenSSH_7.4", "protocol": "2.0"}},
	{name: "setting env", msg: "debug2: Setting env 0: AI_AGENT=claude-code",
		kind: event.SSHEnv, fields: map[string]string{"index": "0", "name": "AI_AGENT", "value": "claude-code"}},
	{name: "setting env with equals in value", msg: "debug2: Setting env 3: FOO=a=b",
		kind: event.SSHEnv, fields: map[string]string{"index": "3", "name": "FOO", "value": "a=b"}},
	{name: "ignoring env", msg: "debug2: Ignoring env request FOO_BAR: disallowed name",
		kind: event.SSHEnv, fields: map[string]string{"name": "FOO_BAR", "ignored": "true", "reason": "disallowed name"}},

	// Lines that must produce nothing.
	{name: "connection from", msg: "Connection from 203.0.113.5 port 51234 on 10.0.0.3 port 22", skipped: true},
	{name: "server listening", msg: "Server listening on 0.0.0.0 port 22.", skipped: true},
	{name: "kex error", msg: "error: kex_exchange_identification: Connection closed by remote host", skipped: true},
	{name: "disconnecting too many", msg: "Disconnecting authenticating user root 198.51.100.62 port 51300: Too many authentication failures [preauth]", skipped: true},
	{name: "pam auth line", msg: "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.9  user=root", skipped: true},
	{name: "debug noise", msg: "debug1: kex: algorithm: curve25519-sha256 [preauth]", skipped: true},
	{name: "embedded newline never parsed", msg: "Accepted publickey for alice from 203.0.113.5 port 51234 ssh2\nSep 11 14:03:22 web-03 sshd[1]: Accepted password for root from 1.1.1.1 port 1 ssh2", skipped: true},
	{name: "truncated accepted", msg: "Accepted publickey for alice from 203.0.113.5", skipped: true},
	{name: "empty", msg: "", skipped: true},
}

func TestParseMessage(t *testing.T) {
	base := Line{TS: now, Host: "web-03", Ident: "sshd-session", PID: 4242}
	for _, c := range msgCases {
		t.Run(c.name, func(t *testing.T) {
			l := base
			l.Msg = c.msg
			ev, ok := ParseMessage(l)
			if c.skipped {
				if ok {
					t.Fatalf("expected no event, got %+v", ev)
				}
				return
			}
			if !ok {
				t.Fatalf("expected event, got none")
			}
			if ev.Kind != c.kind {
				t.Errorf("Kind=%s want %s", ev.Kind, c.kind)
			}
			if ev.User != c.user || ev.SrcIP != c.ip || ev.SrcPort != c.port {
				t.Errorf("user/ip/port = %q/%q/%d want %q/%q/%d", ev.User, ev.SrcIP, ev.SrcPort, c.user, c.ip, c.port)
			}
			if ev.PID != 4242 || ev.Source != Source || !ev.TS.Equal(now) {
				t.Errorf("PID/Source/TS = %d/%q/%s", ev.PID, ev.Source, ev.TS)
			}
			if ev.Field("ident") != "sshd-session" || ev.Field("host") != "web-03" {
				t.Errorf("ident/host = %q/%q", ev.Field("ident"), ev.Field("host"))
			}
			got := map[string]string{}
			for k, v := range ev.Fields {
				if k != "ident" && k != "host" {
					got[k] = v
				}
			}
			if !reflect.DeepEqual(got, c.fields) {
				t.Errorf("Fields=%v want %v", got, c.fields)
			}
		})
	}
}

func TestParseMessageNoHost(t *testing.T) {
	ev, ok := ParseMessage(Line{TS: now, Ident: "sshd", Msg: "Invalid user x from 1.2.3.4 port 5"})
	if !ok {
		t.Fatal("expected event")
	}
	if _, has := ev.Fields["host"]; has {
		t.Error("host key must be absent when the line had no host")
	}
	if ev.PID != 0 {
		t.Errorf("PID=%d want 0", ev.PID)
	}
}

func TestParseDeclareLine(t *testing.T) {
	now := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)
	l, ok := ParseSyslogLine("2026-09-14T06:00:08.401000+00:00 web-03 whotyped-declare[88]: AI_AGENT=claude-code@2.1 user=alice from=203.0.113.5 port=44324", now)
	if !ok {
		t.Fatal("declare line rejected by framing")
	}
	ev, ok := ParseMessage(l)
	if !ok {
		t.Fatal("declare message rejected")
	}
	if ev.Kind != event.SSHEnv || ev.User != "alice" || ev.SrcIP != "203.0.113.5" || ev.SrcPort != 44324 {
		t.Fatalf("got %+v", ev)
	}
	if ev.PID != 0 {
		t.Errorf("PID = %d: the logger pid must never be used as an sshd pid", ev.PID)
	}
	if ev.Field("name") != "AI_AGENT" || ev.Field("value") != "claude-code@2.1" || ev.Field("via") != "sshrc" {
		t.Errorf("fields %v", ev.Fields)
	}
	if ev.Field("uid") != "" {
		t.Errorf("syslog files carry no trusted uid, got %q", ev.Field("uid"))
	}

	// journald supplies the trusted sender uid.
	jl, ok := ParseJournalJSON([]byte(`{"SYSLOG_IDENTIFIER":"whotyped-declare","_PID":"91","_UID":"1001","MESSAGE":"AI_AGENT=codex-cli user=alice from=2001:db8::7 port=50000"}`))
	if !ok {
		t.Fatal("journal declare rejected")
	}
	jev, ok := ParseMessage(jl)
	if !ok || jev.Field("uid") != "1001" || jev.SrcIP != "2001:db8::7" || jev.PID != 0 {
		t.Fatalf("journal declare: ok=%v %+v", ok, jev)
	}

	bad := []string{
		"AI_AGENT=claude code user=alice from=203.0.113.5 port=1",                      // space in value
		"AI_AGENT= user=alice from=203.0.113.5 port=1",                                 // empty value
		"AI_AGENT=x user=alice from=203.0.113.5 port=0",                                // port 0
		"AI_AGENT=x user=alice from=203.0.113.5 port=70000",                            // port out of range
		"AI_AGENT=x user=alice from=203.0.113.5 port=22 Accepted publickey for bob",    // trailing injection
		"AI_AGENT=x user=al ice from=203.0.113.5 port=22",                              // user with space
		"Accepted publickey for alice from 203.0.113.5 port 22 ssh2",                   // sshd text under the hook tag
		"AI_AGENT=" + strings.Repeat("a", 65) + " user=alice from=203.0.113.5 port=22", // too long
	}
	for _, msg := range bad {
		if ev, ok := ParseMessage(Line{TS: now, Ident: DeclareIdent, PID: 5, Msg: msg, UID: -1}); ok {
			t.Errorf("accepted bad declare %q as %+v", msg, ev)
		}
	}
}
