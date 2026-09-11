package procfs

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/readers"
)

// fsFile keeps the passwd tests short.
type fsFile = fs.File

// fsWalk feeds every regular file under fsys to fn.
func fsWalk(fsys fs.FS, fn func(path string, data []byte)) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fn(p, b)
		return nil
	})
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newScanner(fsys fs.FS, c *clock) *Scanner {
	return &Scanner{
		FS:          fsys,
		Pack:        testPack(),
		Resolver:    MapResolver{"api.anthropic.com": {"160.79.104.10", "160.79.104.11"}},
		ReadEnviron: true,
		Now:         c.now,
	}
}

func byPID(evs []event.Event) map[int]event.Event {
	m := map[int]event.Event{}
	for _, e := range evs {
		m[e.PID] = e
	}
	return m
}

func kinds(evs []event.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, string(e.Kind))
	}
	sort.Strings(out)
	return out
}

func TestScanLocalAgent(t *testing.T) {
	m := loadFixture(t, "local-agent")
	c := &clock{t: time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)}
	sc := newScanner(m, c)

	evs, next := sc.Scan(nil)
	if len(evs) != 3 {
		t.Fatalf("want 3 proc.seen, got %d: %+v", len(evs), evs)
	}
	got := byPID(evs)
	for _, pid := range []int{1, 812, 4390, 4400} {
		if _, ok := got[pid]; ok {
			t.Errorf("pid %d must not be emitted", pid)
		}
	}

	e := got[4411]
	if e.Kind != event.ProcSeen || e.Source != "procfs" || e.User != "alice" || e.Ses != 7 || !e.TS.Equal(c.t) {
		t.Errorf("4411 header: %+v", e)
	}
	wantFields := map[string]string{
		"comm": "claude", "exe": "/home/alice/.local/bin/claude", "argv0": "claude",
		"cmd": "claude --dangerously-skip-permissions", "uid": "1000", "loginuid": "1000",
		"ppid": "4400", "agent": "claude-code", "flags": "--dangerously-skip-permissions",
		"tty": "pts/0", "env.CLAUDECODE": "1", "env.CLAUDE_CODE_ENTRYPOINT": "cli",
	}
	for k, v := range wantFields {
		if e.Field(k) != v {
			t.Errorf("4411 %s=%q want %q", k, e.Field(k), v)
		}
	}
	if _, leaked := e.Fields["env.HOME"]; leaked {
		t.Error("unmatched env var leaked into event")
	}

	e = got[4420] // Bash-tool child: agent only via environment
	if e.Field("agent") != "claude-code" || e.Field("env.CLAUDECODE") != "1" || e.Field("flags") != "" || e.Field("comm") != "bash" || e.Field("ppid") != "4411" || e.Field("tty") != "" {
		t.Errorf("4420: %+v", e.Fields)
	}
	if e.Field("cmd") != "/bin/bash -c ls -la /var/log && tail -n 20 /var/log/syslog" {
		t.Errorf("4420 cmd: %q", e.Field("cmd"))
	}

	e = got[4430] // skip flag under a login session, unknown binary
	if e.Field("agent") != "" || e.Field("flags") != "--yolo" || e.Field("loginuid") != "1000" {
		t.Errorf("4430: %+v", e.Fields)
	}

	if len(next) != 3 || next[4411].Start != 500900 || next[4411].Agent != "claude-code" || next[4411].Ses != 7 {
		t.Errorf("next: %+v", next)
	}

	// Same snapshot 10 s later: nothing new.
	c.add(10 * time.Second)
	evs, next2 := sc.Scan(next)
	if len(evs) != 0 {
		t.Errorf("no change should emit nothing, got %+v", evs)
	}
	if next2[4411].LastEmit != next[4411].LastEmit {
		t.Error("LastEmit must not move without an emit")
	}

	// 61 s after first emit: refresh so the correlator keeps LastSeen fresh.
	c.add(51 * time.Second)
	evs, next3 := sc.Scan(next2)
	if len(evs) != 3 || kinds(evs)[0] != "proc.seen" {
		t.Errorf("refresh: %v", kinds(evs))
	}
	if !next3[4411].LastEmit.Equal(c.t) {
		t.Error("refresh must update LastEmit")
	}

	// claude exits: exactly one proc.gone carrying what we knew about it.
	for k := range m {
		if strings.HasPrefix(k, "4411/") {
			delete(m, k)
		}
	}
	c.add(5 * time.Second)
	evs, next4 := sc.Scan(next3)
	if len(evs) != 1 || evs[0].Kind != event.ProcGone || evs[0].PID != 4411 {
		t.Fatalf("gone: %+v", evs)
	}
	g := evs[0]
	if g.User != "alice" || g.Ses != 7 || g.Field("comm") != "claude" || g.Field("agent") != "claude-code" || g.Field("uid") != "1000" {
		t.Errorf("gone payload: %+v", g)
	}
	if _, still := next4[4411]; still || len(next4) != 2 {
		t.Errorf("next after gone: %+v", next4)
	}
}

func TestScanPIDReuse(t *testing.T) {
	m := loadFixture(t, "local-agent")
	c := &clock{t: time.Now()}
	sc := newScanner(m, c)
	_, prev := sc.Scan(nil)

	// Same PID 4411, new start time: the old one is gone and a new one is seen.
	m["4411/stat"] = &fstest.MapFile{Data: []byte(statLine(4411, "claude", "S", 4400, 34816, 999999))}
	c.add(time.Second)
	evs, next := sc.Scan(prev)
	if !equalStrings(kinds(evs), []string{"proc.gone", "proc.seen"}) {
		t.Fatalf("reuse: %v", kinds(evs))
	}
	if evs[0].Kind != event.ProcSeen || evs[1].Kind != event.ProcGone || evs[0].PID != 4411 || evs[1].PID != 4411 {
		t.Errorf("order/pids: %+v", evs)
	}
	if next[4411].Start != 999999 {
		t.Errorf("next start: %d", next[4411].Start)
	}
}

func TestScanTransientListFailure(t *testing.T) {
	c := &clock{t: time.Now()}
	sc := newScanner(loadFixture(t, "local-agent"), c)
	_, prev := sc.Scan(nil)
	sc.FS = failFS{} // an empty MapFS would still list fine; we need ReadDir itself to fail
	evs, next := sc.Scan(prev)
	if len(evs) != 0 || len(next) != len(prev) {
		t.Errorf("transient failure must not emit gone: %d events, next=%v", len(evs), next)
	}
}

type failFS struct{}

func (failFS) Open(string) (fs.File, error) { return nil, errors.New("EIO") }

func TestScanNoEnviron(t *testing.T) {
	c := &clock{t: time.Now()}
	sc := newScanner(loadFixture(t, "local-agent"), c)
	sc.ReadEnviron = false
	evs, _ := sc.Scan(nil)
	got := byPID(evs)
	if _, ok := got[4420]; ok {
		t.Error("env-only match must disappear without environ")
	}
	e, ok := got[4411]
	if !ok || e.Field("agent") != "claude-code" {
		t.Errorf("name match must survive without environ: %+v", e)
	}
	if _, has := e.Fields["env.CLAUDECODE"]; has {
		t.Error("env field present without environ read")
	}
}

func TestScanMinUIDAndReadlinkHook(t *testing.T) {
	c := &clock{t: time.Now()}
	sc := newScanner(loadFixture(t, "local-agent"), c)
	// Flags alone on a system process without a login uid are not interesting.
	if sc.interesting(Proc{UID: 0, LoginUID: -1}, "", nil, []string{"--yolo"}) {
		t.Error("root, no loginuid, flags only should be skipped")
	}
	if !sc.interesting(Proc{UID: 0, LoginUID: 1000}, "", nil, []string{"--yolo"}) {
		t.Error("sudo from an SSH session with flags should be emitted")
	}
	if !sc.interesting(Proc{UID: 0, LoginUID: -1}, "claude-code", nil, nil) {
		t.Error("agent match always wins")
	}
	if !sc.interesting(Proc{UID: 0, LoginUID: -1}, "", map[string]string{"AI_AGENT": "x"}, nil) {
		t.Error("declared agent always wins")
	}
	// With a readlink hook that denies everything, exe is empty but detection holds.
	sc.Readlink = func(string) (string, error) { return "", errors.New("EACCES") }
	evs, _ := sc.Scan(nil)
	e := byPID(evs)[4411]
	if e.Field("exe") != "" || e.Field("agent") != "claude-code" {
		t.Errorf("hook: %+v", e.Fields)
	}
}

func TestScanHumanAndMCP(t *testing.T) {
	for _, tree := range []string{"human-admin", "mcp-remote"} {
		c := &clock{t: time.Now()}
		sc := newScanner(loadFixture(t, tree), c)
		evs, next := sc.Scan(nil)
		if len(evs) != 0 || len(next) != 0 {
			t.Errorf("%s: want no proc events, got %+v", tree, evs)
		}
		nevs, nnext := sc.ScanNet(nil)
		if len(nevs) != 0 || len(nnext) != 0 {
			t.Errorf("%s: want no net events, got %+v", tree, nevs)
		}
	}
}

func TestScanNet(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)}
	sc := newScanner(loadFixture(t, "local-agent"), c)

	evs, next := sc.ScanNet(nil)
	if len(evs) != 2 {
		t.Fatalf("want 2 net.conn, got %+v", evs)
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].Field("dst") < evs[j].Field("dst") })

	a := evs[0] // attributed to claude via fd/3 -> socket:[54321]
	if a.Kind != event.NetConn || a.Source != "procfs" || a.PID != 4411 || a.Ses != 7 || a.User != "alice" || !a.TS.Equal(c.t) {
		t.Errorf("attributed header: %+v", a)
	}
	for k, v := range map[string]string{"dst": "160.79.104.10", "dst_port": "443", "host": "api.anthropic.com", "agent": "claude-code", "uid": "1000", "comm": "claude", "loginuid": "1000", "state": "established"} {
		if a.Field(k) != v {
			t.Errorf("attributed %s=%q want %q", k, a.Field(k), v)
		}
	}

	u := evs[1] // v4-mapped SYN_SENT, no fd owns inode 54399: uid from the socket row only
	if u.PID != 0 || u.Ses != 0 || u.User != "alice" || u.Field("dst") != "160.79.104.11" || u.Field("uid") != "1000" || u.Field("comm") != "" || u.Field("state") != "syn_sent" {
		t.Errorf("unattributed: %+v", u)
	}

	if len(next) != 2 || !next[54321] || !next[54399] {
		t.Errorf("next: %v", next)
	}
	// Same sockets again: emitted once per inode.
	evs, next2 := sc.ScanNet(next)
	if len(evs) != 0 || len(next2) != 2 {
		t.Errorf("repeat: %+v %v", evs, next2)
	}
	// Socket closes: inode drops out of next so a later reuse is reported again.
	m := loadFixture(t, "local-agent")
	m["net/tcp6"] = &fstest.MapFile{Data: []byte("  sl  local_address remote_address st ...\n")}
	sc.FS = m
	_, next3 := sc.ScanNet(next2)
	if len(next3) != 1 || !next3[54321] {
		t.Errorf("after close: %v", next3)
	}
	// Resolver without answers: nothing matches, nothing tracked.
	sc.Resolver = MapResolver{}
	evs, next4 := sc.ScanNet(nil)
	if len(evs) != 0 || len(next4) != 0 {
		t.Errorf("empty resolver: %+v", evs)
	}
	// No net files at all: prev is returned as-is.
	sc.FS = fstest.MapFS{}
	evs, next5 := sc.ScanNet(next2)
	if evs != nil || len(next5) != 2 {
		t.Errorf("missing net: %+v %v", evs, next5)
	}
}

func TestReaderPortable(t *testing.T) {
	r := New(testPack(), Options{})
	if r.Name() != "procfs" || r.Interval != 5*time.Second || r.NetInterval != 10*time.Second || r.opts.ProcRoot != "/proc" || r.opts.PasswdPath != "/etc/passwd" || r.opts.ResolveTTL != 10*time.Minute {
		t.Errorf("defaults: %+v", r)
	}
	var _ readers.Reader = r
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	out := make(chan event.Event, 1024)
	err := r.Run(ctx, out)
	if runtime.GOOS != "linux" {
		if !errors.Is(err, readers.ErrUnsupportedPlatform) {
			t.Errorf("non-linux Run: %v", err)
		}
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("linux Run should stop on ctx: %v", err)
	}
	if r2 := New(testPack(), Options{ProcRoot: "/nonexistent-proc"}); r2.Run(context.Background(), out) == nil {
		t.Error("missing proc root must error")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
