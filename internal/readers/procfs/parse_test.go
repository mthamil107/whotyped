package procfs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mthamil107/whotyped/internal/rules"
)

const fixtureRoot = "../../../testdata/procfs"

// testPack is a small stand-in for rules/agents.yaml + apihosts.yaml.
func testPack() *rules.Pack {
	return &rules.Pack{
		Agents: []rules.Agent{
			{
				ID:           "claude-code",
				ProcessNames: []string{"claude"},
				ArgvContains: []string{"@anthropic-ai/claude-code"},
				EnvVars:      []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"},
				EnvAIAgent:   []string{"claude-code"},
				SkipFlags:    []string{"--dangerously-skip-permissions", "--permission-mode bypassPermissions"},
			},
			{
				ID:           "codex-cli",
				ProcessNames: []string{"codex", "codex-linux-sandbox"},
				EnvVars:      []string{"CODEX_SANDBOX_NETWORK_DISABLED=1", "CODEX_SANDBOX"},
				SkipFlags:    []string{"--full-auto", "--yolo", "--dangerously-bypass-approvals-and-sandbox"},
			},
			{
				ID:           "gemini-cli",
				ProcessNames: []string{"gemini"},
				EnvVars:      []string{"GEMINI_CLI=1"},
				SkipFlags:    []string{"--yolo", "--approval-mode=yolo"},
			},
			{ID: "aider", ProcessNames: []string{"aider"}, SkipFlags: []string{"--yes-always"}},
			{ID: "disabled-agent", ProcessNames: []string{"bash"}, Disabled: true},
		},
		APIHosts: []rules.Host{
			{Host: "api.anthropic.com", Agent: "claude-code"},
			{Host: "api.openai.com", Agent: "codex-cli"},
			{CIDR: "34.0.0.0/8", Port: 443, Vendor: "google"},
			{Host: "127.0.0.1", Port: 11434, Vendor: "ollama"},
			{Host: "disabled.example", Disabled: true},
		},
	}
}

// loadFixture copies a fixture tree into a MapFS so tests can mutate it.
func loadFixture(t *testing.T, name string) fstest.MapFS {
	t.Helper()
	src := os.DirFS(fixtureRoot + "/" + name)
	m := fstest.MapFS{}
	err := fsWalk(src, func(p string, data []byte) { m[p] = &fstest.MapFile{Data: data} })
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return m
}

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		in      string
		v6      bool
		ip      string
		port    int
		wantErr bool
	}{
		{"0100007F:0016", false, "127.0.0.1", 22, false},
		{"0A684FA0:01BB", false, "160.79.104.10", 443, false},
		{"0700000A:C822", false, "10.0.0.7", 51234, false},
		{"00000000000000000000000001000000:0016", true, "::1", 22, false},
		{"0000000000000000FFFF00000100007F:1F90", true, "127.0.0.1", 8080, false}, // v4-mapped is unmapped
		{"004706260000000000000000E5841068:01BB", true, "2606:4700::6810:84e5", 443, false},
		{"0100007F:0016", true, "", 0, true}, // length mismatch
		{"ZZZZZZZZ:0016", false, "", 0, true},
		{"0100007F", false, "", 0, true},
	}
	for _, c := range cases {
		ip, port, err := parseHexAddr(c.in, c.v6)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if ip != c.ip || port != c.port {
			t.Errorf("%s: got %s:%d want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestParseNetTCP(t *testing.T) {
	in := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18001 1 0000000000000000 100 0 0 10 0
   1: 0700000A:C822 0A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 20 4 30 10 -1
   2: 0700000A:C823 0B684FA0:01BB 02 00000000:00000001 80:00000000 00000001  1001        0 54399 1 0000000000000000 20 4 30 10 -1
   3: 0700000A:C824 0A684FA0:01BB 06 00000000:00000000 03:00001234 00000000     0        0 0 3 0000000000000000
   garbage line
`
	socks, err := ParseNetTCP(strings.NewReader(in), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []Sock{
		{LocalIP: "10.0.0.7", LocalPort: 51234, RemoteIP: "160.79.104.10", RemotePort: 443, State: TCPEstablished, UID: 1000, Inode: 54321},
		{LocalIP: "10.0.0.7", LocalPort: 51235, RemoteIP: "160.79.104.11", RemotePort: 443, State: TCPSynSent, UID: 1001, Inode: 54399},
	}
	if !reflect.DeepEqual(socks, want) {
		t.Errorf("got %+v\nwant %+v", socks, want)
	}

	in6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18002 1 0000000000000000 100 0 0 10 0
   1: 00470626000000000000000001000000:D431 004706260000000000000000E5841068:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 61000 1 0000000000000000 20 4 30 10 -1
`
	socks, err = ParseNetTCP(strings.NewReader(in6), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 1 || socks[0].RemoteIP != "2606:4700::6810:84e5" || socks[0].LocalIP != "2606:4700::1" || socks[0].Inode != 61000 {
		t.Errorf("tcp6: got %+v", socks)
	}
}

// statLine mirrors the fixture generator's /proc/PID/stat layout.
func statLine(pid int, comm, state string, ppid, tty int, start uint64) string {
	return fmt.Sprintf("%d (%s) %s %d %d %d %d %d 4194560 812 0 3 0 45 12 0 0 20 0 1 0 %d 22540288 1301 18446744073709551615 94000000000 94000000100 140720000000 0 0 0 0 4096 81923 0 0 0 17 1 0 0 0 0 0 94000000200 94000000300 94000000400 140720000100 140720000200 140720000200 140720000300 0\n",
		pid, comm, state, ppid, pid, pid, tty, pid, start)
}

func TestParseStat(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		comm  string
		ppid  int
		tty   string
		start uint64
		err   bool
	}{
		{"sshd priv comm with spaces and brackets", statLine(4390, "sshd: alice [priv]", "S", 812, 0, 500100), "sshd: alice [priv]", 812, "", 500100, false},
		{"nested parens in comm", statLine(77, "(a) b)", "R", 1, 34816, 42), "(a) b)", 1, "pts/0", 42, false},
		{"plain", statLine(4411, "claude", "S", 4400, 34817, 500900), "claude", 4400, "pts/1", 500900, false},
		{"short", "12 (x) S 1 2 3", "", 0, "", 0, true},
		{"no parens", "12 x S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21", "", 0, "", 0, true},
	}
	for _, c := range cases {
		var p Proc
		err := parseStat(&p, c.line)
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v", c.name, err)
			continue
		}
		if c.err {
			continue
		}
		if p.Comm != c.comm || p.PPID != c.ppid || p.TTY != c.tty || p.StartTicks != c.start {
			t.Errorf("%s: got comm=%q ppid=%d tty=%q start=%d", c.name, p.Comm, p.PPID, p.TTY, p.StartTicks)
		}
	}
	// status Name wins over the stat comm when both are present.
	p := Proc{}
	parseStatus(&p, []byte("Name:\tsshd-session\nPPid:\t812\nUid:\t0\t0\t0\t0\n"))
	if err := parseStat(&p, statLine(4390, "sshd: alice [priv]", "S", 812, 0, 1)); err != nil {
		t.Fatal(err)
	}
	if p.Comm != "sshd-session" || p.PPID != 812 {
		t.Errorf("status precedence: %+v", p)
	}
}

func TestTTYName(t *testing.T) {
	cases := map[int]string{0: "", 34816: "pts/0", 34817: "pts/1", 35072: "pts/256", 1025: "tty1", 1088: "ttyS0", 5<<8 | 1: "dev/5:1"}
	for nr, want := range cases {
		if got := ttyName(nr); got != want {
			t.Errorf("ttyName(%d)=%q want %q", nr, got, want)
		}
	}
}

func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("A=1\x00B=\x00=bad\x00NOEQ\x00A=2\x00"))
	want := map[string]string{"A": "1", "B": "", "NOEQ": ""}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("got %v want %v", env, want)
	}
	if got := splitNUL([]byte("claude\x00--flag\x00")); !reflect.DeepEqual(got, []string{"claude", "--flag"}) {
		t.Errorf("splitNUL: %q", got)
	}
	if got := splitNUL(nil); got != nil {
		t.Errorf("splitNUL(nil)=%q", got)
	}
}

func TestListPIDs(t *testing.T) {
	fsys := os.DirFS(fixtureRoot + "/local-agent")
	pids, err := ListPIDs(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 812, 4390, 4400, 4411, 4420, 4430}
	if !reflect.DeepEqual(pids, want) {
		t.Errorf("got %v want %v", pids, want)
	}
	for name, ok := range map[string]bool{"1": true, "4411": true, "0": false, "01": false, "self": false, "net": false, "": false} {
		if _, got := pidName(name); got != ok {
			t.Errorf("pidName(%q)=%v want %v", name, got, ok)
		}
	}
}

func TestReadProcFixture(t *testing.T) {
	fsys := os.DirFS(fixtureRoot + "/local-agent")
	p, err := ReadProc(fsys, 4411)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != 4411 || p.PPID != 4400 || p.UID != 1000 || p.Comm != "claude" ||
		p.Exe != "/home/alice/.local/bin/claude" ||
		p.Cmdline != "claude --dangerously-skip-permissions" ||
		!reflect.DeepEqual(p.Argv, []string{"claude", "--dangerously-skip-permissions"}) ||
		p.Env["CLAUDECODE"] != "1" || p.Env["HOME"] != "/home/alice" ||
		p.LoginUID != 1000 || p.SessionID != 7 || p.StartTicks != 500900 || p.TTY != "pts/0" {
		t.Errorf("4411: %+v", p)
	}
	// systemd: unset loginuid/sessionid, no environ file.
	p, err = ReadProc(fsys, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.LoginUID != -1 || p.SessionID != -1 || p.Env != nil || p.TTY != "" || p.Argv[0] != "/sbin/init" {
		t.Errorf("pid 1: %+v", p)
	}
	if _, err := ReadProc(fsys, 9999); err == nil {
		t.Error("missing pid should error")
	}
	// A readlink hook takes precedence and its failure means "unreadable", not "read the file".
	hook := func(name string) (string, error) {
		if name == "4411/exe" {
			return "/opt/claude/claude", nil
		}
		return "", errors.New("EACCES")
	}
	p, _ = readProc(fsys, hook, 4411, false)
	if p.Exe != "/opt/claude/claude" || p.Env != nil {
		t.Errorf("hook: %+v", p)
	}
	p, _ = readProc(fsys, hook, 4400, false)
	if p.Exe != "" {
		t.Errorf("hook failure should yield empty exe, got %q", p.Exe)
	}
	// sessionid absent (audit not compiled in) reads as 0 = unknown.
	m := loadFixture(t, "local-agent")
	delete(m, "4411/sessionid")
	if p, _ := ReadProc(m, 4411); p.SessionID != 0 {
		t.Errorf("missing sessionid: %d", p.SessionID)
	}
}

func TestSocketInodes(t *testing.T) {
	fsys := os.DirFS(fixtureRoot + "/local-agent")
	if got := SocketInodes(fsys, 4411); !reflect.DeepEqual(got, []uint64{54321}) {
		t.Errorf("4411: %v", got)
	}
	if got := SocketInodes(fsys, 4420); got != nil {
		t.Errorf("4420 (pipes only): %v", got)
	}
	if got := SocketInodes(fsys, 9999); got != nil {
		t.Errorf("missing: %v", got)
	}
	hook := func(name string) (string, error) {
		if name == "812/fd/3" {
			return "socket:[777]", nil
		}
		return "", errors.New("EACCES")
	}
	if got := socketInodes(fsys, hook, 812); !reflect.DeepEqual(got, []uint64{777}) {
		t.Errorf("hook: %v", got)
	}
	// MapFS with a real symlink is read through fs.ReadLinkFS, no fixture fallback.
	m := fstest.MapFS{
		"50/fd/3": &fstest.MapFile{Data: []byte("socket:[9001]"), Mode: os.ModeSymlink},
		"50/fd/4": &fstest.MapFile{Data: []byte(strings.Repeat("x", 5000))}, // oversized regular file ignored
	}
	if got := SocketInodes(m, 50); !reflect.DeepEqual(got, []uint64{9001}) {
		t.Errorf("symlink: %v", got)
	}
}

func TestMatch(t *testing.T) {
	pack := testPack()
	cases := []struct {
		name  string
		p     Proc
		agent string
		env   map[string]string
		flags []string
	}{
		{"claude by comm with skip flag",
			Proc{Comm: "claude", Argv: []string{"claude", "--dangerously-skip-permissions"}, Cmdline: "claude --dangerously-skip-permissions"},
			"claude-code", nil, []string{"--dangerously-skip-permissions"}},
		{"node wrapper via argv_contains",
			Proc{Comm: "node", Argv: []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, Cmdline: "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"},
			"claude-code", nil, nil},
		{"python3 wrapper via path segment",
			Proc{Comm: "python3", Argv: []string{"python3", "/home/u/.local/bin/aider", "--yes-always"}, Cmdline: "python3 /home/u/.local/bin/aider --yes-always"},
			"aider", nil, []string{"--yes-always"}},
		{"non-wrapper does not use argv segments",
			Proc{Comm: "less", Argv: []string{"less", "/home/u/.local/bin/aider"}, Cmdline: "less /home/u/.local/bin/aider"},
			"", nil, nil},
		{"exe basename",
			Proc{Comm: "codex-linux-san", Exe: "/usr/lib/codex/codex-linux-sandbox (deleted)"},
			"codex-cli", nil, nil},
		{"truncated comm alone",
			Proc{Comm: "codex-linux-san"},
			"codex-cli", nil, nil},
		{"argv0 basename",
			Proc{Comm: "gemini", Argv: []string{"/opt/gemini/gemini", "chat"}, Cmdline: "/opt/gemini/gemini chat"},
			"gemini-cli", nil, nil},
		{"env only (bash child of claude)",
			Proc{Comm: "bash", Argv: []string{"bash", "-c", "ls"}, Cmdline: "bash -c ls", Env: map[string]string{"CLAUDECODE": "1", "HOME": "/h"}},
			"claude-code", map[string]string{"CLAUDECODE": "1"}, nil},
		{"env NAME=value mismatch",
			Proc{Comm: "bash", Env: map[string]string{"GEMINI_CLI": "0"}},
			"", nil, nil},
		{"env NAME=value match",
			Proc{Comm: "bash", Env: map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "1"}},
			"codex-cli", map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "1"}, nil},
		{"declared AI_AGENT maps to rule",
			Proc{Comm: "bash", Env: map[string]string{"AI_AGENT": "claude-code@2.1.0"}},
			"claude-code", map[string]string{"AI_AGENT": "claude-code@2.1.0"}, nil},
		{"declared AI_AGENT by id",
			Proc{Comm: "bash", Env: map[string]string{"AI_AGENT": "Gemini-CLI"}},
			"gemini-cli", map[string]string{"AI_AGENT": "Gemini-CLI"}, nil},
		{"declared unknown agent",
			Proc{Comm: "bash", Env: map[string]string{"AI_AGENT": "mystery-bot"}},
			"", map[string]string{"AI_AGENT": "mystery-bot"}, nil},
		{"flags only, unknown binary",
			Proc{Comm: "bash", Argv: []string{"bash", "-c", "gemini --yolo -p hi"}, Cmdline: "bash -c gemini --yolo -p hi"},
			"", nil, []string{"--yolo"}},
		{"disabled rule ignored",
			Proc{Comm: "bash", Argv: []string{"-bash"}, Cmdline: "-bash"},
			"", nil, nil},
		{"human editor",
			Proc{Comm: "vim", Argv: []string{"vim", "x.conf"}, Cmdline: "vim x.conf", Env: map[string]string{"TERM": "xterm"}},
			"", nil, nil},
	}
	for _, c := range cases {
		agent, env, flags := Match(c.p, pack)
		if agent != c.agent || !reflect.DeepEqual(env, c.env) || !reflect.DeepEqual(flags, c.flags) {
			t.Errorf("%s: got (%q, %v, %v) want (%q, %v, %v)", c.name, agent, env, flags, c.agent, c.env, c.flags)
		}
	}
	// nil pack still surfaces AI_AGENT.
	agent, env, flags := Match(Proc{Env: map[string]string{"AI_AGENT": "x"}}, nil)
	if agent != "" || env["AI_AGENT"] != "x" || flags != nil {
		t.Errorf("nil pack: %q %v %v", agent, env, flags)
	}
}

func TestHostFor(t *testing.T) {
	pack := testPack()
	res := MapResolver{"api.anthropic.com": {"160.79.104.10", "2606:4700::6810:84e5"}}
	cases := []struct {
		ip    string
		port  int
		res   Resolver
		host  string
		agent string
		ok    bool
	}{
		{"160.79.104.10", 443, res, "api.anthropic.com", "claude-code", true},
		{"::ffff:160.79.104.10", 443, res, "api.anthropic.com", "claude-code", true},
		{"2606:4700::6810:84e5", 443, res, "api.anthropic.com", "claude-code", true},
		{"160.79.104.10", 8443, res, "", "", false}, // port 0 in rule means 443 only
		{"160.79.104.10", 443, nil, "", "", false},  // hostname rules need a resolver
		{"34.1.2.3", 443, nil, "34.0.0.0/8", "", true},
		{"34.1.2.3", 80, nil, "", "", false},
		{"127.0.0.1", 11434, nil, "127.0.0.1", "", true}, // Ollama only because a rule lists it
		{"127.0.0.1", 443, nil, "", "", false},
		{"10.0.0.5", 22, res, "", "", false},
		{"not-an-ip", 443, res, "", "", false},
	}
	for _, c := range cases {
		host, agent, ok := HostFor(c.ip, c.port, pack, c.res)
		if host != c.host || agent != c.agent || ok != c.ok {
			t.Errorf("HostFor(%s,%d): got (%q,%q,%v) want (%q,%q,%v)", c.ip, c.port, host, agent, ok, c.host, c.agent, c.ok)
		}
	}
	if _, _, ok := HostFor("127.0.0.1", 11434, nil, nil); ok {
		t.Error("nil pack must not match")
	}
}

func TestHostList(t *testing.T) {
	hl := NewHostList(testPack())
	if got := hl.Hosts(); !reflect.DeepEqual(got, []string{"api.anthropic.com", "api.openai.com"}) {
		t.Fatalf("hosts: %v", got)
	}
	calls := map[string]int{}
	hl.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		calls[host]++
		switch host {
		case "api.anthropic.com":
			return []net.IP{net.ParseIP("160.79.104.10").To4(), net.ParseIP("::ffff:160.79.104.11")}, nil
		}
		return nil, errors.New("NXDOMAIN")
	}
	if got := hl.Lookup("api.anthropic.com"); got != nil {
		t.Errorf("before refresh: %v", got)
	}
	hl.Refresh(context.Background())
	if got := hl.Lookup("api.anthropic.com"); !reflect.DeepEqual(got, []string{"160.79.104.10", "160.79.104.11"}) {
		t.Errorf("after refresh: %v", got)
	}
	hl.Refresh(context.Background()) // within TTL: no new lookups for cached hosts
	if calls["api.anthropic.com"] != 1 {
		t.Errorf("anthropic lookups = %d, want 1", calls["api.anthropic.com"])
	}
	if calls["api.openai.com"] != 2 {
		t.Errorf("failed host should be retried each refresh, got %d", calls["api.openai.com"])
	}
	hl.TTL = 0
	hl.Refresh(context.Background())
	if calls["api.anthropic.com"] != 2 {
		t.Errorf("expired entry not refreshed: %d", calls["api.anthropic.com"])
	}
	// Ends via HostFor with the same resolver.
	if _, agent, ok := HostFor("160.79.104.11", 443, testPack(), hl); !ok || agent != "claude-code" {
		t.Errorf("HostFor via HostList: %v %q", ok, agent)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hl.TTL = 0
	hl.Refresh(ctx) // must return without looking anything up
	if calls["api.anthropic.com"] != 2 {
		t.Errorf("cancelled ctx still resolved")
	}
	_ = time.Second
}

func TestParsePasswd(t *testing.T) {
	users := ParsePasswd(strings.NewReader("root:x:0:0:root:/root:/bin/bash\n# comment\nbad line\nalice:x:1000:1000::/home/alice:/bin/bash\ndup:x:1000:1000:::\n"))
	if !reflect.DeepEqual(users, map[int]string{0: "root", 1000: "alice"}) {
		t.Errorf("got %v", users)
	}
	lookup := NewPasswdLookup(func() (fsFile, error) {
		return os.DirFS(fixtureRoot + "/local-agent").Open("etc/passwd")
	})
	if lookup(1000) != "alice" || lookup(1001) != "bob" || lookup(0) != "root" || lookup(4242) != "4242" {
		t.Errorf("lookup: %s %s %s %s", lookup(1000), lookup(1001), lookup(0), lookup(4242))
	}
	broken := NewPasswdLookup(func() (fsFile, error) { return nil, errors.New("ENOENT") })
	if broken(1000) != "1000" {
		t.Errorf("broken passwd should fall back to uid")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate(strings.Repeat("a", 600), 512); len(got) != 512 {
		t.Errorf("len %d", len(got))
	}
	s := strings.Repeat("é", 300) // 2 bytes each
	if got := truncate(s, 511); len(got) != 510 || !strings.HasSuffix(got, "é") {
		t.Errorf("utf8 boundary: len %d", len(got))
	}
	if got := truncate("short", 512); got != "short" {
		t.Errorf("short: %q", got)
	}
}
