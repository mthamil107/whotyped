// Package check implements `whotyped check`: it inspects sshd_config, auditd,
// /proc and file permissions, validates the config and rule packs, and
// reports which clue families can actually fire on this host. Parsers are
// portable and fixture-tested; anything that touches the live system is
// behind build tags in check_linux.go.
package check

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/whotyped/whotyped/internal/config"
	"github.com/whotyped/whotyped/internal/rules"
)

// Result statuses.
const (
	StatusPass = "pass"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Exit codes (ARCHITECTURE.md section 7).
const (
	ExitOK        = 0
	ExitDegraded  = 1
	ExitCannotRun = 2
	ExitNeedsRoot = 4
)

// Result is one finding.
type Result struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail | skip
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
	// Optional marks a warn about a capability the design treats as opt-in
	// (the DEBUG1 banner). It is reported but does not degrade the exit code.
	Optional bool `json:"optional,omitempty"`
}

// Families are the clue families reported in Coverage.
var Families = []string{"banner", "rhythm", "pty", "style", "process", "flags", "network", "identity"}

// Report is the outcome of Run.
type Report struct {
	Results  []Result        `json:"results"`
	Coverage map[string]bool `json:"coverage"` // family -> can fire on this host
	ExitCode int             `json:"exit_code"`
}

// ExecFunc runs a command and returns its output. Tests inject canned
// output; Linux uses os/exec with a timeout.
type ExecFunc func(name string, args ...string) (stdout, stderr string, err error)

// Options controls Run.
type Options struct {
	ConfigPath string         // used when Config is nil; "" means config.DefaultPath
	Config     *config.Config // pre-loaded config (tests, or the run command)
	Probe      bool           // also run `sshd -T` (needs root) for the effective sshd settings
	FS         fs.FS          // root filesystem view ("etc/ssh/sshd_config"); nil = platform default
	Exec       ExecFunc       // command runner; nil = platform default (none on non-Linux)
}

// tri is a fact we may not know.
type tri int

const (
	unknown tri = iota
	yes
	no
)

func triOf(b bool) tri {
	if b {
		return yes
	}
	return no
}

// facts is everything the coverage logic needs, gathered by the probes.
type facts struct {
	cfg *config.Config

	sshd        *SSHDSettings
	journal     tri
	authLog     tri
	auditdUnit  tri
	auditLog    tri
	auditRule64 tri
	auditRule32 tri
	procRead    tri
	procEnviron tri
	root        tri
	stateDir    tri
	configOK    bool
	rulesOK     bool
}

type runner struct {
	opts    Options
	results []Result
	f       facts
}

func (r *runner) add(res Result) { r.results = append(r.results, res) }

func (r *runner) pass(name, detail string) {
	r.add(Result{Name: name, Status: StatusPass, Detail: detail})
}
func (r *runner) warn(name, detail, fix string) {
	r.add(Result{Name: name, Status: StatusWarn, Detail: detail, Fix: fix})
}
func (r *runner) fail(name, detail, fix string) {
	r.add(Result{Name: name, Status: StatusFail, Detail: detail, Fix: fix})
}
func (r *runner) skip(name, detail string) {
	r.add(Result{Name: name, Status: StatusSkip, Detail: detail})
}

// Run performs every check and returns the report. It never modifies the
// system; see Fix.
func Run(opts Options) Report {
	r := &runner{opts: opts}
	if r.opts.FS == nil {
		r.opts.FS = defaultFS()
	}
	if r.opts.Exec == nil {
		r.opts.Exec = defaultExec()
	}
	r.checkConfig()
	r.checkRules()
	r.checkSSHD()
	r.checkSSHLogSource()
	r.checkAuditd()
	r.checkProcfs()
	r.checkStateDir()
	cov := r.coverage()
	return Report{Results: r.results, Coverage: cov, ExitCode: exitCode(r.results)}
}

func exitCode(results []Result) int {
	code := ExitOK
	for _, res := range results {
		switch res.Status {
		case StatusFail:
			return ExitCannotRun
		case StatusWarn:
			if !res.Optional {
				code = ExitDegraded
			}
		}
	}
	return code
}

// ---------------------------------------------------------------------------
// config and rules (portable)

func (r *runner) checkConfig() {
	cfg := r.opts.Config
	if cfg == nil {
		path := r.opts.ConfigPath
		if path == "" {
			path = config.DefaultPath
		}
		loaded, err := config.Load(path)
		if err != nil {
			r.fail("config", err.Error(), "fix the YAML; unknown keys and bad durations are rejected")
			r.f.cfg = &loaded
			return
		}
		cfg = &loaded
	}
	r.f.cfg = cfg
	if err := cfg.Validate(); err != nil {
		r.fail("config", err.Error(), "see deploy/config.example.yaml for every key and its allowed values")
		return
	}
	r.f.configOK = true
	switch {
	case cfg.Path == "":
		r.pass("config", "in-memory configuration is valid")
	case !cfg.Loaded:
		r.pass("config", cfg.Path+" not found; built-in defaults in effect")
	default:
		r.pass("config", cfg.Path+" is valid")
	}
}

func (r *runner) checkRules() {
	var dirs []string
	if r.f.cfg != nil {
		dirs = append(dirs, r.f.cfg.Rules.Dirs...)
		if extra := r.f.cfg.Allowlist.ExtraFile; extra != "" {
			// ExtraFile is a single file; Load takes directories. Validate it
			// separately so a typo there is still reported.
			if data, err := os.ReadFile(extra); err != nil {
				r.warn("rules.extra_file", extra+": "+err.Error(), "create the file or clear allowlist.extra_file")
			} else if _, err := rules.ParseFile(extra, data); err != nil {
				r.fail("rules.extra_file", err.Error(), "fix the allowlist file")
			}
		}
	}
	pack, err := rules.Load(dirs...)
	if err != nil {
		r.fail("rules", err.Error(), "fix or remove the offending file in rules.dirs")
		return
	}
	if errs := rules.Validate(pack); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		r.fail("rules", strings.Join(msgs, "; "), "run `whotyped rules validate <dir>` after each edit")
		return
	}
	r.f.rulesOK = true
	r.pass("rules", fmt.Sprintf("pack %s: %d agents, %d banners, %d styles, %d api hosts, %d profiles (dirs: %s)",
		pack.Version, len(pack.Agents), len(pack.Banners), len(pack.Styles), len(pack.APIHosts), len(pack.Profiles),
		strings.Join(dirs, ", ")))
	if r.f.cfg != nil {
		enabled := map[string]bool{}
		for _, id := range r.f.cfg.Allowlist.ProfilesEnabled {
			enabled[id] = true
			if pack.ProfileByID(id) == nil {
				r.warn("rules.profiles", fmt.Sprintf("allowlist.profiles_enabled names unknown profile %q", id), "check the id against rules/allowlist.yaml")
			}
		}
		// A profile that suppresses behaviour clues for any source is a
		// policy hole, not a policy: report every enabled one still lacking
		// users/src_cidrs/fingerprints.
		var loose []string
		for _, w := range rules.Lint(pack) {
			id, _, _ := strings.Cut(strings.TrimPrefix(w, "profile "), " ")
			if enabled[id] {
				loose = append(loose, w)
			}
		}
		if len(loose) > 0 {
			r.warn("rules.profiles.scope", strings.Join(loose, "; "),
				"add users or src_cidrs to each profile in an override file under rules.dirs")
		}
	}
}

// ---------------------------------------------------------------------------
// sshd (file parsing portable; version and -T need exec)

var opensshVersionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func (r *runner) checkSSHD() {
	r.checkSSHDVersion()

	if r.opts.FS == nil {
		r.skip("sshd.config", "no filesystem view on this platform")
		return
	}
	settings, err := ParseSSHDConfigFS(r.opts.FS, "etc/ssh/sshd_config")
	if err != nil {
		r.warn("sshd.config", "/etc/ssh/sshd_config: "+err.Error(), "run as root, or pass --probe to use `sshd -T`")
	} else {
		detail := fmt.Sprintf("parsed %d file(s)", len(settings.Files))
		if len(settings.Unresolved) > 0 {
			detail += "; unresolved Include: " + strings.Join(settings.Unresolved, " ")
		}
		if settings.MatchSeen {
			detail += "; Match blocks present (only global settings evaluated)"
		}
		r.pass("sshd.config", detail)
		r.f.sshd = &settings
	}

	if r.opts.Probe {
		r.probeSSHDEffective()
	}

	if r.f.sshd == nil {
		return
	}
	s := r.f.sshd
	level := s.EffectiveLogLevel()
	switch {
	case s.AtLeastDebug1():
		r.pass("sshd.loglevel", "LogLevel "+level+": session, connection and client banner lines are logged")
	case s.AtLeastVerbose():
		r.add(Result{Name: "sshd.loglevel", Status: StatusWarn, Optional: true,
			Detail: "LogLevel " + level + ": sessions and connections are logged; the client software banner is logged only at DEBUG1, so the banner clue family (SSH libraries such as paramiko, +35) is unavailable",
			Fix:    "optional: set `LogLevel DEBUG1` in " + SSHDDropInPath + " (chattier logs) and reload sshd"})
	default:
		r.warn("sshd.loglevel", "LogLevel "+level+": sshd does not log \"Starting session\" lines, so the rhythm and pty clue families cannot fire for remote sessions",
			"set `LogLevel VERBOSE` (whotyped check --fix installs "+SSHDDropInPath+") and reload sshd")
	}
	if s.AcceptsAIAgent() {
		r.pass("sshd.acceptenv", "AcceptEnv accepts AI_AGENT: clients can declare an agent")
	} else {
		r.warn("sshd.acceptenv", "AcceptEnv does not accept AI_AGENT: declared agents cannot identify themselves; everything relies on inference",
			"add `AcceptEnv AI_AGENT` (whotyped check --fix installs "+SSHDDropInPath+") and reload sshd")
	}
	if strings.EqualFold(s.PermitUserEnvironment, "yes") {
		r.warn("sshd.permituserenvironment", "PermitUserEnvironment yes: a client can set arbitrary variables, so AI_AGENT (and its absence) is client-controlled",
			"expected for declared agents anyway; note that identity clues are self-reported")
	}
	if len(s.Includes) == 0 && r.opts.FS != nil {
		r.warn("sshd.include", "sshd_config has no Include line; the drop-in "+SSHDDropInPath+" would be ignored",
			"add `Include /etc/ssh/sshd_config.d/*.conf` at the top of /etc/ssh/sshd_config, or set the two keywords there directly")
	}
}

func (r *runner) checkSSHDVersion() {
	if r.opts.Exec == nil {
		r.skip("sshd.version", "no command runner on this platform")
		return
	}
	out := ""
	for _, cmd := range [][]string{{"sshd", "-V"}, {"ssh", "-V"}} {
		stdout, stderr, _ := r.opts.Exec(cmd[0], cmd[1:]...)
		if m := opensshVersionRe.FindString(stdout + stderr); m != "" {
			out = strings.TrimSpace(firstLine(stderr + stdout))
			break
		}
	}
	if out == "" {
		r.warn("sshd.version", "could not determine the OpenSSH version (sshd -V / ssh -V)", "install openssh-server; whotyped reads its logs")
		return
	}
	detail := out
	if major, minor, ok := parseOpenSSHVersion(out); ok {
		if versionAtLeast(major, minor, 9, 8) {
			detail += " (>= 9.8: per-connection process is sshd-session, handled)"
		} else {
			detail += " (< 9.8: per-connection process is sshd)"
		}
	}
	r.pass("sshd.version", detail)
}

// parseOpenSSHVersion extracts major.minor from a version banner such as
// "OpenSSH_10.0p2 Ubuntu-1" or "OpenSSH_9.8". The portable suffix (p1, p2)
// and vendor tail are ignored. Numeric on purpose: compared as strings,
// "10" sorts before "9" and OpenSSH 10.x would be reported as < 9.8.
func parseOpenSSHVersion(s string) (major, minor int, ok bool) {
	m := opensshVersionRe.FindStringSubmatch(s)
	if len(m) != 3 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func versionAtLeast(major, minor, wantMajor, wantMinor int) bool {
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// probeSSHDEffective replaces the parsed settings with `sshd -T` output,
// which is what sshd actually runs with. Needs root.
func (r *runner) probeSSHDEffective() {
	if r.opts.Exec == nil {
		r.skip("sshd.effective", "no command runner on this platform")
		return
	}
	if r.f.root == no {
		r.skip("sshd.effective", "`sshd -T` needs root")
		return
	}
	stdout, stderr, err := r.opts.Exec("sshd", "-T")
	if err != nil || strings.TrimSpace(stdout) == "" {
		r.warn("sshd.effective", "`sshd -T` failed: "+strings.TrimSpace(firstLine(stderr))+errString(err), "run whotyped check as root")
		return
	}
	s := ParseSSHDConfig(strings.NewReader(stdout))
	s.Files = []string{"sshd -T"}
	if r.f.sshd != nil {
		s.Includes = r.f.sshd.Includes
	}
	r.f.sshd = &s
	r.pass("sshd.effective", "effective settings from `sshd -T`: LogLevel "+s.EffectiveLogLevel()+", AcceptEnv "+strings.Join(s.AcceptEnv, " "))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

// ---------------------------------------------------------------------------
// sshd log source, auditd, procfs, state dir

func (r *runner) checkSSHLogSource() {
	cfg := r.f.cfg
	if r.opts.Exec != nil {
		if _, _, err := r.opts.Exec("journalctl", "--version"); err == nil {
			r.f.journal = yes
		} else {
			r.f.journal = no
		}
	}
	if r.opts.FS != nil {
		candidates := []string{"var/log/auth.log", "var/log/secure"}
		if cfg != nil && cfg.Readers.SSHLog.File != "" {
			candidates = append([]string{strings.TrimPrefix(cfg.Readers.SSHLog.File, "/")}, candidates...)
		}
		r.f.authLog = no
		for _, c := range candidates {
			if readable(r.opts.FS, c) {
				r.f.authLog = yes
				r.pass("sshlog.file", "/"+c+" is readable")
				break
			}
		}
	}
	switch {
	case r.f.journal == unknown && r.f.authLog == unknown:
		r.skip("sshlog", "sshd log source probes are Linux-only")
	case cfg != nil && cfg.Readers.SSHLog.Source == "journald" && r.f.journal != yes:
		r.fail("sshlog", "readers.sshlog.source is journald but journalctl is not available", "install systemd-journal or set source: file")
	case cfg != nil && cfg.Readers.SSHLog.Source == "file" && r.f.authLog != yes:
		r.fail("sshlog", "readers.sshlog.source is file but "+cfg.Readers.SSHLog.File+" is not readable", "fix the path or permissions, or set source: auto")
	case r.f.journal == yes:
		r.pass("sshlog", "journalctl available: sshd log via `journalctl -f -o json`")
	case r.f.authLog == yes:
		r.pass("sshlog", "sshd log via auth log file")
	default:
		r.fail("sshlog", "no sshd log source: journalctl missing and no readable /var/log/auth.log or /var/log/secure", "install rsyslog or run whotyped as root / in the adm group")
	}
}

func (r *runner) checkAuditd() {
	cfg := r.f.cfg
	if cfg != nil && !cfg.Readers.Auditd.Enabled {
		r.skip("auditd", "readers.auditd.enabled is false")
		return
	}
	if r.opts.FS != nil {
		has64, has32, keys := r.auditRulesFromFS()
		r.f.auditRule64, r.f.auditRule32 = triOf(has64), triOf(has32)
		switch {
		case has64 && has32:
			r.pass("auditd.rules", "execve rules for b64 and b32 present (keys: "+strings.Join(keys, ",")+")")
		case has64:
			r.warn("auditd.rules", "execve rule present for b64 only; 32-bit binaries are not recorded", "whotyped check --fix installs "+AuditRulesPath+" with both ABIs")
		default:
			r.warn("auditd.rules", "no always,exit execve rule in /etc/audit/rules.d or audit.rules: command text for remote sessions is unavailable",
				"whotyped check --fix installs "+AuditRulesPath+"; then `augenrules --load`")
		}
	}
	if r.opts.Exec != nil {
		stdout, _, _ := r.opts.Exec("systemctl", "is-active", "auditd")
		if strings.TrimSpace(stdout) == "active" {
			r.f.auditdUnit = yes
			r.pass("auditd.unit", "auditd is active")
		} else {
			r.f.auditdUnit = no
			r.warn("auditd.unit", "auditd is not active ("+strings.TrimSpace(firstLine(stdout))+")", "install auditd and `systemctl enable --now auditd`")
		}
	}
	if r.opts.FS != nil {
		file := "var/log/audit/audit.log"
		if cfg != nil && cfg.Readers.Auditd.File != "" {
			file = strings.TrimPrefix(cfg.Readers.Auditd.File, "/")
		}
		if readable(r.opts.FS, file) {
			r.f.auditLog = yes
			r.pass("auditd.log", "/"+file+" is readable")
		} else {
			r.f.auditLog = no
			r.warn("auditd.log", "/"+file+" is not readable", "run whotyped as root (audit.log is 0600 root by default)")
		}
	}
	if r.opts.FS == nil && r.opts.Exec == nil {
		r.skip("auditd", "auditd probes are Linux-only")
	}
}

func (r *runner) auditRulesFromFS() (has64, has32 bool, keys []string) {
	files, _ := fs.Glob(r.opts.FS, "etc/audit/rules.d/*.rules")
	sort.Strings(files)
	files = append(files, "etc/audit/audit.rules")
	seen := map[string]bool{}
	for _, name := range files {
		f, err := r.opts.FS.Open(name)
		if err != nil {
			continue
		}
		a, b, k := ParseAuditRules(f)
		f.Close()
		has64 = has64 || a
		has32 = has32 || b
		for _, key := range k {
			seen[key] = true
		}
	}
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return has64, has32, keys
}

func (r *runner) checkProcfs() {
	cfg := r.f.cfg
	if cfg != nil && !cfg.Readers.Procfs.Enabled {
		r.skip("procfs", "readers.procfs.enabled is false")
		return
	}
	if r.opts.FS == nil {
		r.skip("procfs", "/proc probes are Linux-only")
		return
	}
	if readable(r.opts.FS, "proc/self/status") || readable(r.opts.FS, "proc/1/status") {
		r.f.procRead = yes
	} else {
		r.f.procRead = no
		r.fail("procfs", "/proc is not readable", "mount procfs; whotyped cannot see processes without it")
		return
	}
	// PID 1's environ is readable only by root; it stands in for "can read
	// other users' environments", which is where AI_AGENT and CLAUDECODE live.
	if _, err := fs.ReadFile(r.opts.FS, "proc/1/environ"); err == nil {
		r.f.procEnviron = yes
		r.f.root = yes
		if cfg != nil && !cfg.Readers.Procfs.ReadEnviron {
			r.warn("procfs.environ", "running as root but readers.procfs.read_environ is false: declared agents (AI_AGENT) and env markers such as CLAUDECODE are not read",
				"set readers.procfs.read_environ: true")
		} else {
			r.pass("procfs.environ", "/proc/*/environ readable (root): process env markers and AI_AGENT declarations are visible")
		}
	} else {
		r.f.procEnviron = no
		if r.f.root == unknown {
			r.f.root = no
		}
		r.warn("procfs.environ", "/proc/1/environ not readable: not root, so other users' environments (AI_AGENT, CLAUDECODE, CURSOR_AGENT) are invisible; only process names and argv are scored",
			"run whotyped as root (systemd unit default) for the identity and proc.agent_env clues")
	}
}

func (r *runner) checkStateDir() {
	cfg := r.f.cfg
	if cfg == nil || cfg.StateDir == "" {
		return
	}
	st, err := os.Stat(cfg.StateDir)
	switch {
	case err != nil:
		r.f.stateDir = no
		r.warn("state_dir", cfg.StateDir+": "+err.Error(), "mkdir -p "+cfg.StateDir+" (the systemd unit uses StateDirectory=whotyped)")
	case !st.IsDir():
		r.f.stateDir = no
		r.fail("state_dir", cfg.StateDir+" is not a directory", "point state_dir at a directory")
	default:
		tmp, err := os.CreateTemp(cfg.StateDir, ".whotyped-check-*")
		if err != nil {
			r.f.stateDir = no
			r.fail("state_dir", cfg.StateDir+" is not writable: "+err.Error(), "chown the directory to the whotyped user")
			return
		}
		tmp.Close()
		os.Remove(tmp.Name())
		r.f.stateDir = yes
		r.pass("state_dir", cfg.StateDir+" is writable")
	}
}

// readable opens and closes a file to test read permission without
// slurping it.
func readable(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	st, err := f.Stat()
	if err == nil && st.IsDir() {
		f.Close()
		return false
	}
	// Opening a 0600 file as another user fails at Open on a real FS; on a
	// MapFS it always succeeds, which is what fixtures want.
	buf := make([]byte, 1)
	_, err = f.Read(buf)
	f.Close()
	return err == nil || err == io.EOF
}

// ---------------------------------------------------------------------------
// coverage

// coverage decides which clue families can fire, adds one result per
// family, and returns the map.
func (r *runner) coverage() map[string]bool {
	f := &r.f
	cov := map[string]bool{}
	cfg := f.cfg
	procfsOn := cfg == nil || cfg.Readers.Procfs.Enabled
	netconnOn := cfg == nil || cfg.Readers.Netconn.Enabled
	auditdOn := cfg == nil || cfg.Readers.Auditd.Enabled
	environOn := cfg == nil || cfg.Readers.Procfs.ReadEnviron

	sshdKnown := f.sshd != nil
	verbose := sshdKnown && f.sshd.AtLeastVerbose()
	debug1 := sshdKnown && f.sshd.AtLeastDebug1()
	acceptEnv := sshdKnown && f.sshd.AcceptsAIAgent()
	auditLive := auditdOn && f.auditRule64 == yes && f.auditdUnit != no && f.auditLog != no
	procLive := procfsOn && f.procRead == yes
	environLive := procLive && environOn && f.procEnviron == yes

	cov["banner"] = debug1
	cov["rhythm"] = verbose
	cov["pty"] = verbose
	cov["style"] = auditLive || procLive
	cov["flags"] = auditLive || procLive
	cov["process"] = procLive
	cov["network"] = netconnOn && procLive
	cov["identity"] = acceptEnv && environLive

	unknownPlatform := !sshdKnown && f.procRead == unknown
	for _, fam := range Families {
		name := "coverage." + fam
		if cov[fam] {
			r.pass(name, coverageDetail(fam, true, f))
			continue
		}
		if unknownPlatform {
			r.skip(name, "cannot be determined on this platform")
			continue
		}
		res := Result{Name: name, Status: StatusWarn, Detail: coverageDetail(fam, false, f), Fix: coverageFix(fam, f)}
		if fam == "banner" {
			res.Optional = true
		}
		if fam == "style" && auditdOn && f.auditRule64 == yes && procLive && f.auditdUnit == no {
			res.Detail += " (procfs still catches long-running commands)"
		}
		r.add(res)
	}
	return cov
}

func coverageDetail(fam string, live bool, f *facts) string {
	switch fam {
	case "banner":
		if live {
			return "client banners logged at DEBUG1: banner.library / banner.automation / banner.human can fire"
		}
		return "sshd LogLevel below DEBUG1: banner clues (paramiko, AsyncSSH, ssh2js, Go, +35) cannot fire; an MCP paramiko server scores ~70 instead of 88 without it"
	case "rhythm":
		if live {
			return "\"Starting session\" lines logged: exec-channel bursts, regularity and sub-second gaps are measured"
		}
		return "sshd LogLevel below VERBOSE: no \"Starting session\" lines, so rhythm clues cannot fire"
	case "pty":
		if live {
			return "session types logged: pty.none / pty.interactive can fire"
		}
		return "sshd LogLevel below VERBOSE: PTY allocation per session is unknown"
	case "style":
		if live {
			return "command text available (auditd execve and/or procfs): heredoc, compound, tool_wrapper, pager_guard can fire"
		}
		return "no command text source: neither an active auditd execve rule nor readable /proc"
	case "flags":
		if live {
			return "argv available: proc.skip_flags (--dangerously-skip-permissions, --yolo, --trust-all-tools) can fire"
		}
		return "no argv source: skip flags cannot be seen"
	case "process":
		if live {
			return "/proc readable: proc.agent_name and proc.agent_env can fire"
		}
		return "/proc not scanned: local agent processes are invisible"
	case "network":
		if live {
			return "/proc/net readable: net.ai_api connections to AI API hosts are attributed"
		}
		return "netconn disabled or /proc unreadable: AI API connections are not seen"
	case "identity":
		if live {
			return "AcceptEnv AI_AGENT and readable environs: declared agents are classified as declared_agent"
		}
		switch {
		case f.sshd != nil && !f.sshd.AcceptsAIAgent():
			return "sshd does not accept AI_AGENT: a client's declaration never reaches the session"
		case f.procEnviron != yes:
			return "AI_AGENT would be accepted but environments are not readable (not root or read_environ false)"
		default:
			return "identity clue unavailable"
		}
	}
	return ""
}

func coverageFix(fam string, f *facts) string {
	switch fam {
	case "banner":
		return "optional: LogLevel DEBUG1 in " + SSHDDropInPath + " and reload sshd; otherwise rely on rhythm+pty+style"
	case "rhythm", "pty":
		return "LogLevel VERBOSE (whotyped check --fix) and reload sshd"
	case "style", "flags":
		return "install auditd with " + AuditRulesPath + " (whotyped check --fix; augenrules --load) or enable readers.procfs"
	case "process":
		return "enable readers.procfs and ensure /proc is mounted"
	case "network":
		return "enable readers.netconn (needs readers.procfs)"
	case "identity":
		if f.sshd != nil && !f.sshd.AcceptsAIAgent() {
			return "AcceptEnv AI_AGENT (whotyped check --fix) and reload sshd"
		}
		return "run whotyped as root with readers.procfs.read_environ: true"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Fix

// Fix installs the sshd drop-in and audit rules (Linux, root). It writes
// files and prints reload commands; it never restarts a service. The exit
// code is ExitNeedsRoot when not root, ExitCannotRun on other failure.
func Fix(opts Options, w io.Writer) ([]Result, int) {
	return fixPlatform(opts, w)
}

// ---------------------------------------------------------------------------
// Rendering

// Render writes the human-readable table.
func Render(rep Report, w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tDETAIL")
	for _, res := range rep.Results {
		status := strings.ToUpper(res.Status)
		if res.Optional && res.Status == StatusWarn {
			status = "WARN*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", status, res.Name, res.Detail)
		if res.Fix != "" && res.Status != StatusPass {
			fmt.Fprintf(tw, "\t\t  fix: %s\n", res.Fix)
		}
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprint(w, "coverage:")
	for _, fam := range Families {
		mark := "no"
		if rep.Coverage[fam] {
			mark = "yes"
		}
		fmt.Fprintf(w, " %s=%s", fam, mark)
	}
	fmt.Fprintln(w)
	switch rep.ExitCode {
	case ExitOK:
		fmt.Fprintln(w, "result: pass (WARN* marks optional capabilities)")
	case ExitDegraded:
		fmt.Fprintln(w, "result: degraded (exit 1): whotyped runs, but some clue families cannot fire")
	default:
		fmt.Fprintf(w, "result: cannot run (exit %d)\n", rep.ExitCode)
	}
}

// RenderJSON writes the report as indented JSON.
func RenderJSON(rep Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
