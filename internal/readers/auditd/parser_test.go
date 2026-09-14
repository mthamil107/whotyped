package auditd

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

const fixtureDir = "../../../testdata/auditd"

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return string(b)
}

func replayFixture(t *testing.T, name string) []event.Event {
	t.Helper()
	return Replay(strings.NewReader(readFixture(t, name)))
}

func TestParseRecordHeader(t *testing.T) {
	rec, ok := ParseRecord(`type=CWD msg=audit(1757600000.123:4567): cwd="/home/alice"` + "\r\n")
	if !ok {
		t.Fatal("expected ok")
	}
	if rec.Type != "CWD" || rec.Serial != 4567 {
		t.Errorf("type/serial = %q/%d", rec.Type, rec.Serial)
	}
	want := time.Date(2025, 9, 11, 14, 13, 20, 123_000_000, time.UTC)
	if !rec.TS.Equal(want) {
		t.Errorf("ts = %v, want %v", rec.TS, want)
	}
	if rec.Fields["cwd"] != "/home/alice" {
		t.Errorf("cwd = %q", rec.Fields["cwd"])
	}
	// node= prefix (ausearch / remote logging) is tolerated.
	if rec, ok := ParseRecord(`node=web-03 type=CWD msg=audit(1.000:2): cwd="/"`); !ok || rec.Type != "CWD" {
		t.Errorf("node= prefix not handled: %+v %v", rec, ok)
	}
	for _, bad := range []string{"", "garbage", "type=X", "type=X msg=audit(abc:1): a=b", "type=X msg=audit(1.0:x): a=b", "Sep 11 sshd[1]: hello"} {
		if _, ok := ParseRecord(bad); ok {
			t.Errorf("ParseRecord(%q) should fail", bad)
		}
	}
}

func TestParseFields(t *testing.T) {
	tests := []struct {
		name string
		line string
		key  string
		want string
	}{
		{"bare", `type=SYSCALL msg=audit(1.000:1): pid=3102 ses=7`, "pid", "3102"},
		{"quoted with spaces", `type=SYSCALL msg=audit(1.000:1): subj="system_u:system r" exe="/usr/bin/ls"`, "subj", "system_u:system r"},
		{"quoted after spaces", `type=SYSCALL msg=audit(1.000:1): subj="a b" exe="/usr/bin/ls"`, "exe", "/usr/bin/ls"},
		{"hex comm", `type=SYSCALL msg=audit(1.000:1): comm=6D792070726F67 exe="/x"`, "comm", "my prog"},
		{"hex cwd", `type=CWD msg=audit(1.000:1): cwd=2F746D702F6D7920646972`, "cwd", "/tmp/my dir"},
		{"numeric ses not decoded", `type=SYSCALL msg=audit(1.000:1): ses=1234 pid=10`, "ses", "1234"},
		{"numeric auid not decoded", `type=SYSCALL msg=audit(1.000:1): auid=1000`, "auid", "1000"},
		{"pointer aN in SYSCALL not decoded", `type=SYSCALL msg=audit(1.000:1): a0=55D0C1A3`, "a0", "55D0C1A3"},
		{"execve aN decoded", `type=EXECVE msg=audit(1.000:1): argc=1 a0=6C73`, "a0", "ls"},
		{"lowercase hex is not hex", `type=EXECVE msg=audit(1.000:1): argc=1 a0=6c73`, "a0", "6c73"},
		{"odd length is not hex", `type=EXECVE msg=audit(1.000:1): argc=1 a0=6C7`, "a0", "6C7"},
		{"unset auid", `type=SYSCALL msg=audit(1.000:1): auid=unset ses=4294967295`, "auid", "-1"},
		{"unset ses", `type=SYSCALL msg=audit(1.000:1): auid=unset ses=4294967295`, "ses", "-1"},
		{"tty none", `type=SYSCALL msg=audit(1.000:1): tty=(none) ses=7`, "tty", "(none)"},
		{"empty value", `type=X msg=audit(1.000:1): a= b=2`, "b", "2"},
		{"nested acct", `type=USER_START msg=audit(1.000:1): pid=3055 msg='op=PAM:session_open acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.5 terminal=ssh res=success'`, "acct", "alice"},
		{"nested op", `type=USER_START msg=audit(1.000:1): pid=3055 msg='op=PAM:session_open acct="alice" res=success'`, "op", "PAM:session_open"},
		{"nested res", `type=USER_START msg=audit(1.000:1): pid=3055 msg='op=PAM:session_open acct="alice" res=success'`, "res", "success"},
		{"outer pid kept with nested", `type=USER_START msg=audit(1.000:1): pid=3055 msg='op=x acct="alice"'`, "pid", "3055"},
		{"nested hex acct", `type=USER_START msg=audit(1.000:1): msg='op=x acct=616C69636520626F62 res=success'`, "acct", "alice bob"},
		{"nested unterminated", `type=USER_START msg=audit(1.000:1): msg='op=x acct="alice"`, "acct", "alice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := ParseRecord(tc.line)
			if !ok {
				t.Fatalf("parse failed")
			}
			if got := rec.Fields[tc.key]; got != tc.want {
				t.Errorf("Fields[%q] = %q, want %q (all: %v)", tc.key, got, tc.want, rec.Fields)
			}
		})
	}
}

func TestParseEnrichedTail(t *testing.T) {
	line := `type=SYSCALL msg=audit(1.000:1): arch=c000003e syscall=59 auid=1000 uid=1000 comm="ls" exe="/usr/bin/ls"` +
		"\x1d" + `ARCH=x86_64 SYSCALL=execve AUID="alice" UID="alice"`
	rec, ok := ParseRecord(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if rec.Fields["exe"] != "/usr/bin/ls" {
		t.Errorf("exe = %q; tail leaked into fields?", rec.Fields["exe"])
	}
	if _, leaked := rec.Fields["AUID"]; leaked {
		t.Error("ENRICHED key leaked into Fields")
	}
	if rec.Enriched["AUID"] != "alice" || rec.Enriched["SYSCALL"] != "execve" || rec.Enriched["ARCH"] != "x86_64" {
		t.Errorf("enriched = %v", rec.Enriched)
	}
	if _, ok := ParseRecord(`type=CWD msg=audit(1.000:1): cwd="/"`); !ok {
		t.Error("record without tail must still parse")
	}
	if rec, _ := ParseRecord(`type=CWD msg=audit(1.000:1): cwd="/"`); rec.Enriched != nil {
		t.Error("Enriched must be nil without a tail")
	}
}

func TestProctitleHexAndNULSplit(t *testing.T) {
	p := NewParser()
	var evs []event.Event
	evs = append(evs, p.Feed(`type=SYSCALL msg=audit(1.000:1): arch=c000003e syscall=59 success=yes pid=1 ppid=0 auid=1000 uid=1000 ses=7 tty=pts0 comm="ls" exe="/usr/bin/ls"`)...)
	evs = append(evs, p.Feed(`type=PROCTITLE msg=audit(1.000:1): proctitle=6C73002D6C61002F746D702F6D7920646972`)...)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1 (PROCTITLE closes the group)", len(evs))
	}
	ev := evs[0]
	if ev.Field("argv0") != "ls" || ev.Field("cmd") != "ls -la /tmp/my dir" || ev.Field("argc") != "3" {
		t.Errorf("argv from proctitle: argv0=%q cmd=%q argc=%q", ev.Field("argv0"), ev.Field("cmd"), ev.Field("argc"))
	}
	if ev.Field("argv_from") != "proctitle" {
		t.Error("expected argv_from=proctitle marker")
	}
	// Single-arg proctitle is quoted, not hex.
	p = NewParser()
	p.Feed(`type=SYSCALL msg=audit(2.000:2): arch=c000003e syscall=59 pid=1 auid=1000 uid=1000 ses=7`)
	evs = p.Feed(`type=PROCTITLE msg=audit(2.000:2): proctitle="/usr/bin/true"`)
	if len(evs) != 1 || evs[0].Field("cmd") != "/usr/bin/true" || evs[0].Field("argc") != "1" {
		t.Errorf("single-arg proctitle: %+v", evs)
	}
}

func TestChunkedArgs(t *testing.T) {
	evs := replayFixture(t, "execve-chunked-arg.log")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	want := "sh -c x=" + strings.Repeat("A", 40) + " && echo done"
	if got := evs[0].Field("cmd"); got != want {
		t.Errorf("cmd = %q\nwant %q", got, want)
	}
	if evs[0].Field("argc") != "3" {
		t.Errorf("argc = %q", evs[0].Field("argc"))
	}
	// Chunks arriving out of order in one record are re-ordered by index.
	argv, _ := argvFromExecve([]Record{{Type: "EXECVE", Fields: map[string]string{
		"argc": "2", "a0": "x", "a1[1]": "world", "a1_len": "10", "a1[0]": "hello",
	}}})
	if strings.Join(argv, "|") != "x|helloworld" {
		t.Errorf("argv = %v", argv)
	}
}

func TestExecveDetection(t *testing.T) {
	tests := []struct {
		name   string
		header string
		exec   bool
	}{
		{"x86_64 execve", "arch=c000003e syscall=59", true},
		{"x86_64 execveat", "arch=c000003e syscall=322", true},
		{"x86_64 openat", "arch=c000003e syscall=257", false},
		{"i386 execve", "arch=40000003 syscall=11", true},
		{"i386 execveat", "arch=40000003 syscall=358", true},
		{"i386 59 is not execve", "arch=40000003 syscall=59", false},
		{"aarch64 execve", "arch=c00000b7 syscall=221", true},
		{"aarch64 execveat", "arch=c00000b7 syscall=281", true},
		{"aarch64 59 is not execve", "arch=c00000b7 syscall=59", false},
		{"unknown arch by enriched name", "arch=c0000015 syscall=11\x1dARCH=ppc64le SYSCALL=execve", true},
		{"unknown arch by enriched execveat", "arch=c0000015 syscall=362\x1dARCH=ppc64le SYSCALL=execveat", true},
		{"unknown arch, other name", "arch=c0000015 syscall=5\x1dARCH=ppc64le SYSCALL=open", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser()
			line := `type=SYSCALL msg=audit(1.000:1): ` + strings.Replace(tc.header, "\x1d", ` success=yes pid=1 auid=1000 uid=1000 ses=7 comm="x" exe="/x"`+"\x1d", 1)
			if !strings.Contains(tc.header, "\x1d") {
				line += ` success=yes pid=1 auid=1000 uid=1000 ses=7 comm="x" exe="/x"`
			}
			p.Feed(line)
			evs := p.Feed(`type=PROCTITLE msg=audit(1.000:1): proctitle="x"`)
			if got := len(evs) == 1; got != tc.exec {
				t.Errorf("execve = %v, want %v", got, tc.exec)
			}
		})
	}
	// An EXECVE record alone (SYSCALL record lost) is still an execve.
	p := NewParser()
	p.Feed(`type=EXECVE msg=audit(1.000:9): argc=1 a0="ls"`)
	if evs := p.FlushAll(); len(evs) != 1 || evs[0].Field("argv0") != "ls" {
		t.Errorf("EXECVE-only group: %+v", evs)
	}
}

func TestGroupingInterleavedSerials(t *testing.T) {
	p := NewParser()
	var evs []event.Event
	feed := func(l string) { evs = append(evs, p.Feed(l)...) }
	// Records of 4567 and 4568 interleave; both must be assembled completely.
	feed(`type=SYSCALL msg=audit(1.000:4567): arch=c000003e syscall=59 success=yes pid=10 ppid=1 auid=1000 uid=1000 ses=7 tty=pts0 comm="ls" exe="/usr/bin/ls"`)
	feed(`type=SYSCALL msg=audit(1.001:4568): arch=c000003e syscall=59 success=yes pid=11 ppid=1 auid=1000 uid=1000 ses=7 tty=pts0 comm="cat" exe="/usr/bin/cat"`)
	feed(`type=EXECVE msg=audit(1.000:4567): argc=2 a0="ls" a1="-la"`)
	feed(`type=EXECVE msg=audit(1.001:4568): argc=2 a0="cat" a1="/etc/hostname"`)
	feed(`type=CWD msg=audit(1.000:4567): cwd="/home/alice"`)
	feed(`type=CWD msg=audit(1.001:4568): cwd="/tmp"`)
	if len(evs) != 0 {
		t.Fatalf("premature events: %+v", evs)
	}
	feed(`type=PROCTITLE msg=audit(1.001:4568): proctitle=636174002F6574632F686F73746E616D65`)
	if len(evs) != 1 || evs[0].PID != 11 || evs[0].Field("cwd") != "/tmp" || evs[0].Field("cmd") != "cat /etc/hostname" {
		t.Fatalf("4568 not assembled: %+v", evs)
	}
	feed(`type=PROCTITLE msg=audit(1.000:4567): proctitle=6C73002D6C61`)
	if len(evs) != 2 || evs[1].PID != 10 || evs[1].Field("cwd") != "/home/alice" || evs[1].Field("cmd") != "ls -la" {
		t.Fatalf("4567 not assembled: %+v", evs)
	}
	if p.Pending() != 0 {
		t.Errorf("pending groups = %d", p.Pending())
	}
}

func TestGroupClosedBySerialGap(t *testing.T) {
	p := NewParser()
	p.Feed(`type=SYSCALL msg=audit(1.000:100): arch=c000003e syscall=59 success=yes pid=10 auid=1000 uid=1000 ses=7 comm="ls" exe="/usr/bin/ls"`)
	p.Feed(`type=EXECVE msg=audit(1.000:100): argc=1 a0="ls"`)
	// Adjacent serial does not close 100 (interleaving is allowed) …
	if evs := p.Feed(`type=SYSCALL msg=audit(1.001:101): arch=c000003e syscall=257 pid=11 auid=1000 uid=1000 ses=7`); len(evs) != 0 {
		t.Fatalf("adjacent serial closed the group: %+v", evs)
	}
	// … but a record two serials ahead does.
	evs := p.Feed(`type=SYSCALL msg=audit(1.002:102): arch=c000003e syscall=257 pid=12 auid=1000 uid=1000 ses=7`)
	if len(evs) != 1 || evs[0].Field("argv0") != "ls" {
		t.Fatalf("serial gap did not close group 100: %+v", evs)
	}
	// EOE closes explicitly.
	p = NewParser()
	p.Feed(`type=SYSCALL msg=audit(2.000:200): arch=c000003e syscall=59 pid=10 auid=1000 uid=1000 ses=7`)
	p.Feed(`type=EXECVE msg=audit(2.000:200): argc=1 a0="id"`)
	if evs := p.Feed(`type=EOE msg=audit(2.000:200): `); len(evs) != 1 || evs[0].Field("argv0") != "id" {
		t.Fatalf("EOE did not close the group: %+v", evs)
	}
}

func TestFlushByAge(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	p := NewParser()
	p.Now = func() time.Time { return now }
	p.Feed(`type=SYSCALL msg=audit(1.000:300): arch=c000003e syscall=59 success=yes pid=10 auid=1000 uid=1000 ses=7 comm="ls" exe="/usr/bin/ls"`)
	p.Feed(`type=EXECVE msg=audit(1.000:300): argc=1 a0="ls"`)
	if evs := p.Flush(now.Add(1999 * time.Millisecond)); len(evs) != 0 {
		t.Fatalf("flushed too early: %+v", evs)
	}
	evs := p.Flush(now.Add(2 * time.Second))
	if len(evs) != 1 || evs[0].Field("argv0") != "ls" {
		t.Fatalf("age flush: %+v", evs)
	}
	if evs := p.Flush(now.Add(time.Hour)); len(evs) != 0 {
		t.Errorf("double flush: %+v", evs)
	}
	// Custom MaxAge.
	p = NewParser()
	p.Now = func() time.Time { return now }
	p.MaxAge = 500 * time.Millisecond
	p.Feed(`type=EXECVE msg=audit(1.000:301): argc=1 a0="ls"`)
	if evs := p.Flush(now.Add(500 * time.Millisecond)); len(evs) != 1 {
		t.Errorf("custom MaxAge flush: %+v", evs)
	}
}

func TestUserRecords(t *testing.T) {
	evs := replayFixture(t, "user-start-login-end.log")
	if len(evs) != 4 {
		t.Fatalf("events = %d, want 4 (CRED_ACQ ignored): %+v", len(evs), evs)
	}
	type want struct {
		kind     event.Kind
		typ      string
		user     string
		uid      string
		terminal string
	}
	wants := []want{
		{event.AuditLogin, "USER_START", "alice", "", "ssh"},
		{event.AuditLogin, "USER_LOGIN", "", "1000", "/dev/pts/0"},
		{event.AuditLogout, "USER_END", "alice", "", "ssh"},
		{event.AuditLogout, "USER_LOGOUT", "", "1000", "/dev/pts/0"},
	}
	for i, w := range wants {
		ev := evs[i]
		if ev.Kind != w.kind || ev.Field("type") != w.typ || ev.User != w.user || ev.Field("uid") != w.uid || ev.Field("terminal") != w.terminal {
			t.Errorf("[%d] got kind=%s type=%s user=%q uid=%q terminal=%q, want %+v", i, ev.Kind, ev.Field("type"), ev.User, ev.Field("uid"), ev.Field("terminal"), w)
		}
		if ev.PID != 3055 || ev.Ses != 7 || ev.SrcIP != "203.0.113.5" || ev.Source != "auditd" {
			t.Errorf("[%d] pid/ses/srcip/source = %d/%d/%q/%q", i, ev.PID, ev.Ses, ev.SrcIP, ev.Source)
		}
		if ev.Field("res") != "success" || ev.Field("addr") != "203.0.113.5" || ev.Field("hostname") != "203.0.113.5" || ev.Field("exe") != "/usr/sbin/sshd" || ev.Field("auid") != "1000" {
			t.Errorf("[%d] fields = %v", i, ev.Fields)
		}
	}
	if evs[0].Field("op") != "PAM:session_open" || evs[1].Field("op") != "login" || evs[2].Field("op") != "PAM:session_close" {
		t.Errorf("op fields: %q %q %q", evs[0].Field("op"), evs[1].Field("op"), evs[2].Field("op"))
	}
	if !evs[0].TS.Equal(time.Unix(1757600000, 100_000_000)) {
		t.Errorf("ts = %v", evs[0].TS)
	}

	// Non-sshd PAM sessions are ignored; sshd-session (OpenSSH >= 9.8) and
	// terminal=ssh are accepted; ENRICHED ID resolves the USER_LOGIN name.
	cases := []struct {
		line string
		want int
		user string
	}{
		{`type=USER_START msg=audit(1.000:1): pid=1 uid=0 auid=0 ses=9 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'`, 0, ""},
		{`type=USER_START msg=audit(1.000:1): pid=1 uid=1000 auid=1000 ses=7 msg='op=PAM:session_open acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'`, 0, ""},
		{`type=USER_START msg=audit(1.000:1): pid=1 uid=0 auid=1000 ses=7 msg='op=PAM:session_open acct="bob" exe="/usr/lib/openssh/sshd-session" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=success'`, 1, "bob"},
		{`type=USER_LOGIN msg=audit(1.000:1): pid=1 uid=0 auid=1000 ses=7 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/1 res=success'` + "\x1d" + `AUID="carol" UID="root" ID="carol"`, 1, "carol"},
		{`type=USER_LOGIN msg=audit(1.000:1): pid=1 uid=0 auid=1000 ses=7 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/pts/1 res=failed'`, 1, ""},
	}
	for i, c := range cases {
		evs := NewParser().Feed(c.line)
		if len(evs) != c.want {
			t.Errorf("case %d: events = %d, want %d", i, len(evs), c.want)
			continue
		}
		if c.want == 1 && evs[0].User != c.user {
			t.Errorf("case %d: user = %q, want %q", i, evs[0].User, c.user)
		}
	}
	// addr=? must not become a SrcIP.
	evs = NewParser().Feed(cases[4].line)
	if evs[0].SrcIP != "" {
		t.Errorf("SrcIP = %q for addr=?", evs[0].SrcIP)
	}
}

func TestFixtureExecveBasic(t *testing.T) {
	evs := replayFixture(t, "execve-basic.log")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Kind != event.AuditExecve || ev.Source != "auditd" || ev.PID != 3102 || ev.Ses != 7 || ev.User != "" {
		t.Errorf("header: %+v", ev)
	}
	want := map[string]string{
		"argv0": "ls", "cmd": "ls -la /tmp/my dir", "argc": "3", "exe": "/usr/bin/ls", "comm": "ls",
		"cwd": "/home/alice", "tty": "pts0", "uid": "1000", "auid": "1000", "ppid": "3055", "key": "whotyped",
		"success": "yes", "arch": "c000003e", "syscall": "59", "exit": "0", "serial": "4567",
	}
	for k, v := range want {
		if ev.Field(k) != v {
			t.Errorf("Fields[%q] = %q, want %q", k, ev.Field(k), v)
		}
	}
	if _, ok := ev.Fields["auid_name"]; ok {
		t.Error("auid_name must be absent without ENRICHED")
	}
}

func TestFixtureEnriched(t *testing.T) {
	evs := replayFixture(t, "execve-enriched-rhel9.log")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.User != "alice" || ev.Field("auid_name") != "alice" || ev.Field("uid_name") != "alice" {
		t.Errorf("enriched names: user=%q fields=%v", ev.User, ev.Fields)
	}
	if ev.Field("cmd") != "git status --no-pager" || ev.Field("cwd") != "/srv/app" || ev.Field("exe") != "/usr/bin/git" {
		t.Errorf("fields = %v", ev.Fields)
	}
}

func TestFixtureClaudeSkipPerms(t *testing.T) {
	evs := replayFixture(t, "execve-claude-skip-perms.log")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Field("argv0") != "claude" || ev.Ses != 7 || ev.Field("tty") != "(none)" {
		t.Errorf("header fields: %+v", ev)
	}
	if want := "claude --dangerously-skip-permissions -p Fix the failing tests in src/ and commit"; ev.Field("cmd") != want {
		t.Errorf("cmd = %q", ev.Field("cmd"))
	}
}

func TestFixtureBashLcHeredoc(t *testing.T) {
	evs := replayFixture(t, "execve-bash-lc-heredoc.log")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	cmd := evs[0].Field("cmd")
	if !strings.HasPrefix(cmd, "bash -lc cat <<'EOF' > /tmp/x\nhello world\nEOF\n") {
		t.Errorf("cmd = %q", cmd)
	}
	// Injection defence: the decoded text is never re-parsed, so a record-like
	// payload stays an opaque string.
	p := NewParser()
	p.Feed(`type=SYSCALL msg=audit(5.000:50): arch=c000003e syscall=59 pid=1 auid=1000 uid=1000 ses=7 comm="sh" exe="/bin/sh"`)
	payload := "echo\ntype=USER_START msg=audit(5.000:51): pid=9 msg='acct=\"evil\" exe=\"/usr/sbin/sshd\" terminal=ssh res=success'"
	p.Feed(`type=EXECVE msg=audit(5.000:50): argc=3 a0="sh" a1="-c" a2=` + strings.ToUpper(hexOf(payload)))
	evs = p.Feed(`type=PROCTITLE msg=audit(5.000:50): proctitle="sh"`)
	if len(evs) != 1 || evs[0].Kind != event.AuditExecve || !strings.Contains(evs[0].Field("cmd"), "type=USER_START") {
		t.Errorf("injected payload was interpreted: %+v", evs)
	}
	if st := p.Stats(); st.Records != 3 || st.Events != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func hexOf(s string) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(digits[s[i]>>4])
		b.WriteByte(digits[s[i]&15])
	}
	return b.String()
}

func TestFixtureAarch64(t *testing.T) {
	evs := replayFixture(t, "execve-aarch64.log")
	if len(evs) != 1 || evs[0].Field("cmd") != "uname -m" || evs[0].Field("arch") != "c00000b7" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestFixtureMixedSession(t *testing.T) {
	evs := replayFixture(t, "mixed-session.log")
	var execs, logins, logouts, other int
	var last time.Time
	for _, ev := range evs {
		switch ev.Kind {
		case event.AuditExecve:
			execs++
			if ev.Ses != 7 || ev.Field("argv0") != "bash" || !strings.HasPrefix(ev.Field("cmd"), "bash -lc ") || ev.Field("tty") != "(none)" {
				t.Errorf("unexpected execve: %+v", ev)
			}
			if !last.IsZero() {
				if gap := ev.TS.Sub(last); gap < 400*time.Millisecond || gap > 900*time.Millisecond {
					t.Errorf("gap %v outside 0.4-0.9s", gap)
				}
			}
			last = ev.TS
		case event.AuditLogin:
			logins++
			if ev.Ses != 7 || ev.User != "alice" || ev.SrcIP != "203.0.113.5" || ev.PID != 4200 {
				t.Errorf("unexpected login: %+v", ev)
			}
		case event.AuditLogout:
			logouts++
		default:
			other++
		}
	}
	if execs != 12 || logins != 1 || logouts != 1 || other != 0 {
		t.Errorf("execs=%d logins=%d logouts=%d other=%d", execs, logins, logouts, other)
	}
	if evs[0].Kind != event.AuditLogin || evs[len(evs)-1].Kind != event.AuditLogout {
		t.Error("events not in file order")
	}
	// Spot-check the heredoc command survived hex decoding.
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.Field("cmd"), "cat <<'EOF' > /tmp/patch.py\nimport re\n") {
			found = true
		}
	}
	if !found {
		t.Error("heredoc command not found in mixed session")
	}
}

func TestStatsAndMalformed(t *testing.T) {
	p := NewParser()
	p.Feed("")
	p.Feed("not an audit line")
	p.Feed(`type=CRED_ACQ msg=audit(1.000:1): pid=1 msg='op=PAM:setcred acct="alice" exe="/usr/sbin/sshd" terminal=ssh res=success'`)
	p.Feed(`type=USER_START msg=audit(1.000:2): pid=1 ses=7 msg='op=PAM:session_open acct="alice" exe="/usr/sbin/sshd" addr=10.0.0.1 terminal=ssh res=success'`)
	st := p.Stats()
	if st.Lines != 4 || st.Records != 2 || st.Events != 1 || st.Malformed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestCmdCap(t *testing.T) {
	p := NewParser()
	p.Feed(`type=SYSCALL msg=audit(1.000:1): arch=c000003e syscall=59 pid=1 auid=1000 uid=1000 ses=7`)
	p.Feed(`type=EXECVE msg=audit(1.000:1): argc=2 a0="echo" a1="` + strings.Repeat("x", 5000) + `"`)
	evs := p.FlushAll()
	if len(evs) != 1 || len(evs[0].Field("cmd")) != maxCmdLen {
		t.Errorf("cmd len = %d", len(evs[0].Field("cmd")))
	}
}

func TestUnsetSesInEvent(t *testing.T) {
	p := NewParser()
	p.Feed(`type=SYSCALL msg=audit(1.000:1): arch=c000003e syscall=59 pid=812 auid=4294967295 uid=0 ses=4294967295 comm="x" exe="/x"`)
	p.Feed(`type=EXECVE msg=audit(1.000:1): argc=1 a0="x"`)
	evs := p.FlushAll()
	if len(evs) != 1 || evs[0].Ses != -1 || evs[0].Field("auid") != "-1" || evs[0].Field("uid") != "0" {
		t.Errorf("unset handling: %+v", evs)
	}
}

// TestOversizedArgvIsCapped: a 128 KiB argv0 (hex-encoded, so 256 KiB on the
// line) must come out capped at the name limit, the command at 2 KiB, and
// comm at 64 bytes, without the parser holding the whole thing.
func TestOversizedArgvIsCapped(t *testing.T) {
	huge := strings.Repeat("A", 128<<10)
	hexHuge := strings.ToUpper(hex.EncodeToString([]byte(huge + " with space")))
	comm := strings.ToUpper(hex.EncodeToString([]byte(strings.Repeat("c", 200))))
	lines := []string{
		`type=SYSCALL msg=audit(1757600000.100:900): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=4 items=2 ppid=1 pid=2 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=7 comm=` + comm + ` exe="/usr/bin/` + strings.Repeat("e", 400) + `" key="whotyped-exec"`,
		`type=EXECVE msg=audit(1757600000.100:900): argc=2 a0=` + hexHuge + ` a1="x"`,
		`type=PROCTITLE msg=audit(1757600000.100:900): proctitle=` + strings.ToUpper(hex.EncodeToString([]byte("a\x00b"))),
	}
	evs := Replay(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if len(evs) != 1 {
		t.Fatalf("%d events", len(evs))
	}
	ev := evs[0]
	if l := len(ev.Field("argv0")); l != maxNameLen {
		t.Errorf("argv0 len %d", l)
	}
	if l := len(ev.Field("cmd")); l != maxCmdLen {
		t.Errorf("cmd len %d", l)
	}
	if l := len(ev.Field("comm")); l != maxCommLen {
		t.Errorf("comm len %d", l)
	}
	if l := len(ev.Field("exe")); l != maxNameLen {
		t.Errorf("exe len %d", l)
	}
}

// TestReplayFlushesStaleGroups: records whose EOE/PROCTITLE never arrives
// are still emitted once the replay has moved on, not held until EOF.
func TestReplayFlushesStaleGroups(t *testing.T) {
	var b strings.Builder
	// 1500 execve events, none of them closed by PROCTITLE/EOE and each
	// exactly one serial apart, so Feed's two-serials-behind rule never
	// fires on its own.
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&b, "type=SYSCALL msg=audit(1757600000.%03d:%d): arch=c000003e syscall=59 success=yes exit=0 pid=%d auid=1000 uid=1000 ses=7 comm=\"ls\" exe=\"/bin/ls\"\n", i%1000, 1000+i, 3000+i)
	}
	p := NewParser()
	sc := bufio.NewScanner(strings.NewReader(b.String()))
	n, fed := 0, 0
	for sc.Scan() {
		n += len(p.Feed(sc.Text()))
		fed++
	}
	if p.Pending() != 1500-n || n > 1499 {
		t.Fatalf("plain feed: emitted %d pending %d", n, p.Pending())
	}
	evs := Replay(strings.NewReader(b.String()))
	if len(evs) != 1500 {
		t.Fatalf("replay emitted %d events, want 1500", len(evs))
	}
	if evs[0].PID != 3000 || evs[1499].PID != 4499 {
		t.Fatalf("order lost: first pid %d last pid %d", evs[0].PID, evs[1499].PID)
	}
}
