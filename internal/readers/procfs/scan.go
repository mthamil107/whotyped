package procfs

import (
	"bufio"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/whotyped/whotyped/internal/clean"
	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/rules"
)

// Defaults for Scanner zero values.
const (
	DefaultMinUID       = 1000
	DefaultRefreshEvery = 60 * time.Second
	maxCmdLen           = 512
)

// Scanner turns one snapshot of /proc into events. It holds no state itself;
// callers thread the maps returned by Scan/ScanNet back in so the same
// Scanner works for the live daemon and for fixture replay.
type Scanner struct {
	FS       fs.FS                        // rooted at /proc
	Readlink func(string) (string, error) // optional; receives FS-relative names ("4411/exe")
	Pack     *rules.Pack                  // agent + api_hosts rules
	Resolver Resolver                     // for hostname rules; nil = CIDR/literal only
	Now      func() time.Time             // default time.Now
	// ReadEnviron enables /proc/PID/environ reads. Without it env-only
	// agents (bash children carrying CLAUDECODE=1) and AI_AGENT are invisible.
	ReadEnviron bool
	// MinUID is the first ordinary-user uid. Below it, environ is only read
	// for processes with a login uid (sudo from an SSH session) and skip
	// flags alone do not trigger an event. Zero means DefaultMinUID.
	MinUID int
	// RefreshEvery re-emits proc.seen for a still-running process so the
	// correlator keeps LastSeen fresh. Zero means DefaultRefreshEvery.
	RefreshEvery time.Duration
	// UserLookup resolves uid to a name. Default: etc/passwd inside FS
	// (fixtures), else the decimal uid.
	UserLookup func(uid int) string

	userOnce sync.Once
}

// Seen is the per-PID memory between Scan calls.
type Seen struct {
	Start    uint64 // stat starttime; a different value under the same PID is reuse
	UID      int
	Ses      int
	Comm     string
	Agent    string
	LastEmit time.Time
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scanner) minUID() int {
	if s.MinUID > 0 {
		return s.MinUID
	}
	return DefaultMinUID
}

func (s *Scanner) refreshEvery() time.Duration {
	if s.RefreshEvery > 0 {
		return s.RefreshEvery
	}
	return DefaultRefreshEvery
}

func (s *Scanner) user(uid int) string {
	s.userOnce.Do(func() {
		if s.UserLookup == nil {
			s.UserLookup = NewPasswdLookup(func() (fs.File, error) { return s.FS.Open("etc/passwd") })
		}
	})
	return s.UserLookup(uid)
}

// Scan walks every PID and emits proc.seen for processes that match an agent
// rule, carry AI_AGENT, or run with a skip flag under a login session; each
// once per (pid, start) and again every RefreshEvery. proc.gone is emitted
// for tracked PIDs that vanished or were reused. On a failed directory
// listing prev is returned untouched so a transient error never fakes exits.
func (s *Scanner) Scan(prev map[int]Seen) ([]event.Event, map[int]Seen) {
	pids, err := ListPIDs(s.FS)
	if err != nil {
		return nil, prev
	}
	now := s.now()
	next := make(map[int]Seen, len(prev))
	var events, gone []event.Event

	for _, pid := range pids {
		p, err := readProc(s.FS, s.Readlink, pid, false)
		if err != nil {
			continue // exited between ReadDir and open
		}
		if s.ReadEnviron && (p.UID >= s.minUID() || p.LoginUID >= 0) {
			p.Env = readEnviron(s.FS, pid)
		}
		agent, envHits, flags := Match(p, s.Pack)
		if !s.interesting(p, agent, envHits, flags) {
			continue
		}
		old, had := prev[pid]
		if had && old.Start != p.StartTicks {
			gone = append(gone, s.goneEvent(pid, old, now))
			had = false
		}
		cur := Seen{Start: p.StartTicks, UID: p.UID, Ses: p.SessionID, Comm: p.Comm, Agent: agent, LastEmit: old.LastEmit}
		if !had || now.Sub(old.LastEmit) >= s.refreshEvery() {
			events = append(events, s.seenEvent(p, agent, envHits, flags, now))
			cur.LastEmit = now
		}
		next[pid] = cur
	}
	for pid, old := range prev {
		if _, ok := next[pid]; !ok {
			gone = append(gone, s.goneEvent(pid, old, now))
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].PID < gone[j].PID })
	return append(events, gone...), next
}

// interesting decides whether a process is worth an event at all.
func (s *Scanner) interesting(p Proc, agent string, envHits map[string]string, flags []string) bool {
	if agent != "" {
		return true
	}
	if _, declared := envHits["AI_AGENT"]; declared {
		return true
	}
	return len(flags) > 0 && (p.LoginUID >= 0 || p.UID >= s.minUID())
}

func (s *Scanner) seenEvent(p Proc, agent string, envHits map[string]string, flags []string, now time.Time) event.Event {
	ev := event.Event{TS: now, Kind: event.ProcSeen, Source: "procfs", PID: p.PID, Ses: p.SessionID, User: s.user(p.UID)}
	argv0 := ""
	if len(p.Argv) > 0 {
		argv0 = p.Argv[0]
	}
	// Everything below comm= comes from memory the process owner controls:
	// strip terminal escapes and control bytes and cap sizes here, before
	// the values reach the correlator, the alert and an operator's screen.
	ev.Set("comm", clean.Text(p.Comm, clean.MaxComm)).
		Set("exe", clean.Text(p.Exe, clean.MaxName)).
		Set("argv0", clean.Text(argv0, clean.MaxName)).
		Set("cmd", clean.Text(p.Cmdline, maxCmdLen)).
		Set("uid", strconv.Itoa(p.UID)).
		Set("loginuid", strconv.Itoa(p.LoginUID)).
		Set("ppid", strconv.Itoa(p.PPID)).
		Set("agent", agent).
		Set("flags", strings.Join(flags, ","))
	if p.TTY != "" {
		ev.Set("tty", clean.Text(p.TTY, clean.MaxComm))
	}
	for k, v := range envHits {
		if k == "AI_AGENT" {
			// Invalid declarations are forwarded as the marker so the
			// correlator records the attempt without accepting the claim.
			v, _ = clean.AIAgent(v)
		} else {
			v = clean.Text(v, clean.MaxAIAgent)
		}
		ev.Set("env."+k, v)
	}
	return ev
}

func (s *Scanner) goneEvent(pid int, old Seen, now time.Time) event.Event {
	ev := event.Event{TS: now, Kind: event.ProcGone, Source: "procfs", PID: pid, Ses: old.Ses, User: s.user(old.UID)}
	ev.Set("comm", old.Comm).Set("agent", old.Agent).Set("uid", strconv.Itoa(old.UID))
	return ev
}

// ScanNet emits net.conn for every ESTABLISHED/SYN_SENT socket whose remote
// end is an api_hosts rule, once per socket inode. The owning process is found
// through /proc/PID/fd; the inode index is built at most once per call and
// only when a new matching socket exists. prev is returned untouched when
// neither /proc/net/tcp nor tcp6 could be read.
func (s *Scanner) ScanNet(prev map[uint64]bool) ([]event.Event, map[uint64]bool) {
	socks, ok := s.readSocks()
	if !ok {
		return nil, prev
	}
	now := s.now()
	next := make(map[uint64]bool, len(prev))
	var events []event.Event
	var index map[uint64]int

	for _, sk := range socks {
		host, agent, ok := HostFor(sk.RemoteIP, sk.RemotePort, s.Pack, s.Resolver)
		if !ok {
			continue
		}
		next[sk.Inode] = true
		if prev[sk.Inode] {
			continue
		}
		if index == nil {
			index = s.inodeIndex()
		}
		ev := event.Event{TS: now, Kind: event.NetConn, Source: "procfs"}
		uid := sk.UID
		ev.Set("dst", sk.RemoteIP).
			Set("dst_port", strconv.Itoa(sk.RemotePort)).
			Set("host", host).
			Set("agent", agent).
			Set("state", stateName(sk.State))
		if pid, found := index[sk.Inode]; found {
			ev.PID = pid
			if p, err := readProc(s.FS, s.Readlink, pid, false); err == nil {
				uid = p.UID
				ev.Ses = p.SessionID
				ev.Set("comm", p.Comm).Set("loginuid", strconv.Itoa(p.LoginUID))
			}
		}
		ev.Set("uid", strconv.Itoa(uid))
		ev.User = s.user(uid)
		events = append(events, ev)
	}
	return events, next
}

// readSocks reads tcp and tcp6; ok is false only if both are unreadable.
func (s *Scanner) readSocks() ([]Sock, bool) {
	var all []Sock
	ok := false
	for _, f := range []struct {
		name string
		v6   bool
	}{{"net/tcp", false}, {"net/tcp6", true}} {
		fh, err := s.FS.Open(f.name)
		if err != nil {
			continue
		}
		socks, err := ParseNetTCP(fh, f.v6)
		fh.Close()
		if err != nil {
			continue
		}
		ok = true
		all = append(all, socks...)
	}
	return all, ok
}

// inodeIndex maps socket inode to owning PID across all readable fd dirs.
func (s *Scanner) inodeIndex() map[uint64]int {
	index := map[uint64]int{}
	pids, err := ListPIDs(s.FS)
	if err != nil {
		return index
	}
	for _, pid := range pids {
		for _, ino := range socketInodes(s.FS, s.Readlink, pid) {
			if _, dup := index[ino]; !dup { // a forked child shares the fd; keep the parent
				index[ino] = pid
			}
		}
	}
	return index
}

func stateName(st uint8) string {
	switch st {
	case TCPEstablished:
		return "established"
	case TCPSynSent:
		return "syn_sent"
	}
	return strconv.Itoa(int(st))
}

// truncate caps s at max bytes without splitting a UTF-8 sequence.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ParsePasswd reads /etc/passwd-formatted text into uid -> login name.
func ParsePasswd(r io.Reader) map[int]string {
	users := map[int]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if _, dup := users[uid]; !dup {
			users[uid] = f[0]
		}
	}
	return users
}

// NewPasswdLookup returns a uid -> name function backed by open() (an
// /etc/passwd file). The table is cached for 10 minutes and re-read early
// when an unknown uid appears, which is what happens right after useradd.
// Unknown uids resolve to their decimal form.
func NewPasswdLookup(open func() (fs.File, error)) func(uid int) string {
	var (
		mu     sync.Mutex
		table  map[int]string
		loaded time.Time
	)
	const ttl = 10 * time.Minute
	const retry = time.Minute
	load := func(now time.Time) {
		loaded = now
		f, err := open()
		if err != nil {
			if table == nil {
				table = map[int]string{}
			}
			return
		}
		defer f.Close()
		table = ParsePasswd(f)
	}
	return func(uid int) string {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if table == nil || now.Sub(loaded) > ttl {
			load(now)
		}
		name, ok := table[uid]
		if !ok && now.Sub(loaded) > retry {
			load(now)
			name, ok = table[uid]
		}
		if !ok {
			return strconv.Itoa(uid)
		}
		return name
	}
}
