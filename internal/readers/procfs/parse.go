// Package procfs finds AI agent processes and their outbound API connections
// by reading /proc. Every parser here is a pure function over an fs.FS rooted
// at /proc (or an io.Reader), so the package builds and is fixture-tested on
// any OS; only Reader.Run (reader_linux.go) touches the live kernel.
package procfs

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/mthamil107/whotyped/internal/rules"
)

// unsetID is what the kernel reports in loginuid/sessionid when audit never
// assigned one: (uid_t)-1.
const unsetID = 4294967295

// Proc is what we keep from one /proc/PID directory.
type Proc struct {
	PID, PPID, UID int
	Comm           string
	Exe            string // readlink target of /proc/PID/exe, "" when unreadable
	Cmdline        string // Argv joined with single spaces
	Argv           []string
	Env            map[string]string // every variable; rule filtering happens in Match
	LoginUID       int               // -1 when unset (4294967295) or unreadable
	SessionID      int               // -1 when unset (4294967295), 0 when unreadable
	StartTicks     uint64            // stat field 22; disambiguates PID reuse
	TTY            string            // "pts/0", "tty1" or "" (decoded from stat tty_nr)
}

// ListPIDs returns the numeric directory names under the /proc root, ascending.
func ListPIDs(fsys fs.FS) ([]int, error) {
	ents, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if pid, ok := pidName(e.Name()); ok {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

func pidName(name string) (int, bool) {
	if name == "" || (name[0] == '0' && len(name) > 1) {
		return 0, false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || name[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(name)
	return n, err == nil && n > 0
}

// ReadProc reads one process. status and stat must be readable (otherwise
// the process is gone and an error is returned); everything else degrades to
// empty values. environ is included; the Scanner uses readProc to skip it for
// processes that cannot matter.
func ReadProc(fsys fs.FS, pid int) (Proc, error) {
	return readProc(fsys, nil, pid, true)
}

func readProc(fsys fs.FS, readlink func(string) (string, error), pid int, withEnv bool) (Proc, error) {
	dir := strconv.Itoa(pid)
	p := Proc{PID: pid, LoginUID: -1}

	status, err := fs.ReadFile(fsys, dir+"/status")
	if err != nil {
		return p, err
	}
	parseStatus(&p, status)

	stat, err := fs.ReadFile(fsys, dir+"/stat")
	if err != nil {
		return p, err
	}
	if err := parseStat(&p, string(stat)); err != nil {
		return p, err
	}

	if b, err := fs.ReadFile(fsys, dir+"/comm"); err == nil {
		p.Comm = strings.TrimSpace(string(b))
	}
	if b, err := fs.ReadFile(fsys, dir+"/cmdline"); err == nil {
		p.Argv = splitNUL(b)
		p.Cmdline = strings.Join(p.Argv, " ")
	}
	p.LoginUID = readIDFile(fsys, dir+"/loginuid", -1)
	p.SessionID = readIDFile(fsys, dir+"/sessionid", 0)
	p.Exe = readLink(fsys, readlink, dir+"/exe")
	if withEnv {
		p.Env = readEnviron(fsys, pid)
	}
	return p, nil
}

// readEnviron returns the process environment, or nil when unreadable
// (another user's process without CAP_SYS_PTRACE). Not an error.
func readEnviron(fsys fs.FS, pid int) map[string]string {
	b, err := fs.ReadFile(fsys, strconv.Itoa(pid)+"/environ")
	if err != nil {
		return nil
	}
	return parseEnviron(b)
}

// parseStatus takes Name, PPid and the real Uid from /proc/PID/status.
func parseStatus(p *Proc, b []byte) {
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		switch key {
		case "Name":
			p.Comm = strings.TrimSpace(rest)
		case "PPid":
			p.PPID, _ = strconv.Atoi(f[0])
		case "Uid":
			p.UID, _ = strconv.Atoi(f[0])
		}
	}
}

// parseStat reads /proc/PID/stat. The comm field may contain spaces and
// parentheses ("(sshd: alice [priv])"), so fields are counted from the LAST
// ')' onward: index 0 is state (field 3), 1 is ppid (4), 4 is tty_nr (7) and
// 19 is starttime (22).
func parseStat(p *Proc, s string) error {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return errors.New("procfs: malformed stat")
	}
	if p.Comm == "" {
		p.Comm = s[open+1 : end]
	}
	f := strings.Fields(s[end+1:])
	if len(f) < 20 {
		return errors.New("procfs: short stat")
	}
	if p.PPID == 0 {
		p.PPID, _ = strconv.Atoi(f[1])
	}
	if nr, err := strconv.Atoi(f[4]); err == nil {
		p.TTY = ttyName(nr)
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return errors.New("procfs: bad starttime")
	}
	p.StartTicks = start
	return nil
}

// ttyName decodes a Linux dev_t tty_nr into the usual name.
func ttyName(nr int) string {
	if nr <= 0 {
		return ""
	}
	major := (nr >> 8) & 0xfff
	minor := (nr & 0xff) | ((nr >> 12) & 0xfff00)
	switch major {
	case 136, 137, 138, 139: // Unix98 pty slaves
		return "pts/" + strconv.Itoa((major-136)*256+minor)
	case 4:
		if minor < 64 {
			return "tty" + strconv.Itoa(minor)
		}
		return "ttyS" + strconv.Itoa(minor-64)
	}
	return "dev/" + strconv.Itoa(major) + ":" + strconv.Itoa(minor)
}

func splitNUL(b []byte) []string {
	s := strings.TrimRight(string(b), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

func parseEnviron(b []byte) map[string]string {
	env := map[string]string{}
	for _, kv := range splitNUL(b) {
		k, v, _ := strings.Cut(kv, "=")
		if k == "" {
			continue
		}
		if _, dup := env[k]; !dup { // first occurrence wins, like getenv
			env[k] = v
		}
	}
	return env
}

// readIDFile reads loginuid/sessionid: -1 for the kernel's "unset" sentinel,
// missing for an unreadable or absent file (audit not compiled in).
func readIDFile(fsys fs.FS, name string, missing int) int {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return missing
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return missing
	}
	if n >= unsetID {
		return -1
	}
	return int(n)
}

// readLink resolves a /proc symlink. Order: the caller's hook (os.Readlink on
// Linux), fs.ReadLinkFS if the FS supports it, then the fixture convention of
// a small regular file holding the target. The fixture path is guarded so a
// real /proc can never make us read a binary or block on a pipe.
func readLink(fsys fs.FS, hook func(string) (string, error), name string) string {
	if hook != nil {
		t, err := hook(name)
		if err != nil {
			return ""
		}
		return t
	}
	if t, err := fs.ReadLink(fsys, name); err == nil {
		return t
	}
	f, err := fsys.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil || strings.IndexByte(string(b), 0) >= 0 {
		return ""
	}
	t := strings.TrimSpace(string(b))
	if strings.ContainsAny(t, "\n\r") {
		return ""
	}
	return t
}

// TCP socket states from include/net/tcp_states.h.
const (
	TCPEstablished uint8 = 0x01
	TCPSynSent     uint8 = 0x02
)

// Sock is one row of /proc/net/tcp or tcp6.
type Sock struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string // v4-mapped IPv6 is unmapped so it matches IPv4 rules
	RemotePort int
	State      uint8
	UID        int
	Inode      uint64
}

// ParseNetTCP returns the ESTABLISHED and SYN_SENT rows of /proc/net/tcp
// (v6=false) or /proc/net/tcp6 (v6=true). Malformed rows are skipped.
func ParseNetTCP(r io.Reader, v6 bool) ([]Sock, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var out []Sock
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] == "sl" {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil || (uint8(st) != TCPEstablished && uint8(st) != TCPSynSent) {
			continue
		}
		lip, lport, err := parseHexAddr(f[1], v6)
		if err != nil {
			continue
		}
		rip, rport, err := parseHexAddr(f[2], v6)
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Sock{
			LocalIP: lip, LocalPort: lport,
			RemoteIP: rip, RemotePort: rport,
			State: uint8(st), UID: uid, Inode: inode,
		})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0016" (IPv4) or the 32-hex-digit IPv6 form.
// The kernel prints each 32-bit word in host (little-endian) byte order, so
// every 4-byte group is reversed.
func parseHexAddr(s string, v6 bool) (string, int, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, errors.New("procfs: bad address")
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, err
	}
	if (v6 && len(raw) != 16) || (!v6 && len(raw) != 4) {
		return "", 0, errors.New("procfs: address length mismatch")
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", 0, errors.New("procfs: bad address")
	}
	return addr.Unmap().String(), int(port), nil
}

// SocketInodes lists the socket inodes open in /proc/PID/fd. nil when the fd
// directory is unreadable (other user's process without CAP_SYS_PTRACE).
func SocketInodes(fsys fs.FS, pid int) []uint64 {
	return socketInodes(fsys, nil, pid)
}

func socketInodes(fsys fs.FS, hook func(string) (string, error), pid int) []uint64 {
	dir := strconv.Itoa(pid) + "/fd"
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range ents {
		t := readLink(fsys, hook, dir+"/"+e.Name())
		if !strings.HasPrefix(t, "socket:[") || !strings.HasSuffix(t, "]") {
			continue
		}
		if n, err := strconv.ParseUint(t[len("socket:["):len(t)-1], 10, 64); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// Match applies the agent rules to one process. agentID is the first rule
// whose process name, argv substring or env var matched (or the rule mapped
// from a declared AI_AGENT value). envHits holds only rule-listed variables
// plus AI_AGENT when present. flags are the skip flags found in argv, from any
// rule, so a bare `--dangerously-skip-permissions` is reported even when the
// binary name is unknown.
func Match(p Proc, pack *rules.Pack) (agentID string, envHits map[string]string, flags []string) {
	envHits = map[string]string{}
	argv0 := ""
	if len(p.Argv) > 0 {
		argv0 = p.Argv[0]
	}
	names := []string{p.Comm, baseName(p.Exe), baseName(argv0)}
	wrapper := isWrapper(p.Comm)

	if pack != nil {
		for _, a := range pack.Agents {
			if a.Disabled {
				continue
			}
			hit := false
			for _, n := range a.ProcessNames {
				if nameMatches(names, n) || (wrapper && argvHasSegment(p.Argv, n)) {
					hit = true
					break
				}
			}
			if !hit {
				for _, s := range a.ArgvContains {
					if s != "" && strings.Contains(p.Cmdline, s) {
						hit = true
						break
					}
				}
			}
			for _, spec := range a.EnvVars {
				name, want, hasVal := strings.Cut(spec, "=")
				if v, ok := p.Env[name]; ok && (!hasVal || v == want) {
					envHits[name] = v
					hit = true
				}
			}
			for _, f := range a.SkipFlags {
				if f != "" && strings.Contains(p.Cmdline, f) {
					flags = appendUnique(flags, f)
				}
			}
			if hit && agentID == "" {
				agentID = a.ID
			}
		}
	}
	if v, ok := p.Env["AI_AGENT"]; ok {
		envHits["AI_AGENT"] = v
		if agentID == "" {
			agentID = agentForDeclared(v, pack)
		}
	}
	if len(envHits) == 0 {
		envHits = nil
	}
	return agentID, envHits, flags
}

// agentForDeclared maps an AI_AGENT value ("claude-code", "cursor-cli@1.2")
// to a rule id via Agent.EnvAIAgent, falling back to an exact id match.
func agentForDeclared(v string, pack *rules.Pack) string {
	v, _, _ = strings.Cut(strings.TrimSpace(v), "@")
	if v == "" || pack == nil {
		return ""
	}
	for _, a := range pack.Agents {
		if a.Disabled {
			continue
		}
		for _, d := range a.EnvAIAgent {
			if strings.EqualFold(d, v) {
				return a.ID
			}
		}
	}
	for _, a := range pack.Agents {
		if !a.Disabled && strings.EqualFold(a.ID, v) {
			return a.ID
		}
	}
	return ""
}

// isWrapper reports interpreters whose comm hides the real tool name.
func isWrapper(comm string) bool {
	switch comm {
	case "node", "nodejs", "bun", "deno", "python", "python3", "sh", "bash":
		return true
	}
	return strings.HasPrefix(comm, "python3.")
}

// nameMatches compares a rule process name against comm/exe/argv0 basenames.
// comm is truncated to 15 bytes by the kernel, so a longer rule name matches
// a full-length comm prefix ("codex-linux-sandbox" vs "codex-linux-san").
func nameMatches(names []string, rule string) bool {
	if rule == "" {
		return false
	}
	for i, n := range names {
		if n == rule {
			return true
		}
		if i == 0 && len(n) == 15 && len(rule) > 15 && strings.HasPrefix(rule, n) {
			return true
		}
	}
	return false
}

// argvHasSegment reports whether any argument after argv0 has a path segment
// equal to name, e.g. node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js.
func argvHasSegment(argv []string, name string) bool {
	for i := 1; i < len(argv); i++ {
		for _, seg := range strings.Split(argv[i], "/") {
			if seg == name {
				return true
			}
		}
	}
	return false
}

func baseName(s string) string {
	if s == "" {
		return ""
	}
	// exe targets of deleted binaries end in " (deleted)".
	s = strings.TrimSuffix(s, " (deleted)")
	return path.Base(s)
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Resolver answers "which IPs does this rule host currently have?". The Linux
// runtime uses HostList (DNS with a TTL cache); tests use MapResolver.
type Resolver interface {
	Lookup(host string) []string
}

// MapResolver is a static Resolver for tests and offline replay.
type MapResolver map[string][]string

// Lookup implements Resolver.
func (m MapResolver) Lookup(host string) []string { return m[host] }

// HostFor matches a remote endpoint against the api_hosts rules: literal IP
// hosts, CIDRs, and resolver-backed hostnames. Port 0 in a rule means 443.
// Local ports such as Ollama's 11434 match only when a rule lists them.
func HostFor(ip string, port int, pack *rules.Pack, resolver Resolver) (host, agent string, ok bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || pack == nil {
		return "", "", false
	}
	addr = addr.Unmap()
	for _, h := range pack.APIHosts {
		if h.Disabled {
			continue
		}
		want := h.Port
		if want == 0 {
			want = 443
		}
		if port != want {
			continue
		}
		label := h.Host
		if label == "" {
			label = h.CIDR
		}
		if h.CIDR != "" {
			if pfx, err := netip.ParsePrefix(h.CIDR); err == nil && pfx.Contains(addr) {
				return label, h.Agent, true
			}
		}
		if h.Host == "" {
			continue
		}
		if lit, err := netip.ParseAddr(h.Host); err == nil {
			if lit.Unmap() == addr {
				return label, h.Agent, true
			}
			continue
		}
		if resolver == nil {
			continue
		}
		for _, s := range resolver.Lookup(h.Host) {
			if a, err := netip.ParseAddr(s); err == nil && a.Unmap() == addr {
				return label, h.Agent, true
			}
		}
	}
	return "", "", false
}
