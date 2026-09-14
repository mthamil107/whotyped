package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/whotyped/whotyped/internal/config"
)

// fixtureFS loads testdata/<name> into a MapFS so tests can add /proc and
// /var/log entries that do not belong in the repository.
func fixtureFS(t *testing.T, name string, extra map[string]string) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	root := os.DirFS(filepath.Join("testdata", name))
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		m[p] = &fstest.MapFile{Data: data}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range extra {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func fakeExec(auditdActive bool, journal bool) ExecFunc {
	return func(name string, args ...string) (string, string, error) {
		switch name {
		case "sshd":
			if len(args) > 0 && args[0] == "-V" {
				return "", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n", nil
			}
			if len(args) > 0 && args[0] == "-T" {
				return "port 22\nloglevel VERBOSE\nacceptenv LANG\nacceptenv LC_*\nacceptenv AI_AGENT\npermituserenvironment no\n", "", nil
			}
		case "ssh":
			return "", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\n", nil
		case "systemctl":
			if auditdActive {
				return "active\n", "", nil
			}
			return "inactive\n", "", errors.New("exit status 3")
		case "journalctl":
			if journal {
				return "systemd 255 (255.4-1ubuntu8)\n", "", nil
			}
			return "", "", errors.New("not found")
		}
		return "", "", errors.New("unexpected command " + name)
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	cfg.Rules.Dirs = nil
	return &cfg
}

func byName(rep Report) map[string]Result {
	m := map[string]Result{}
	for _, r := range rep.Results {
		m[r.Name] = r
	}
	return m
}

func TestRunFullyProvisionedHost(t *testing.T) {
	fsys := fixtureFS(t, "ubuntu", map[string]string{
		"proc/1/status":           "Name:\tsystemd\n",
		"proc/1/environ":          "PATH=/usr/bin\x00",
		"var/log/auth.log":        "",
		"var/log/audit/audit.log": "",
	})
	rep := Run(Options{Config: testConfig(t), FS: fsys, Exec: fakeExec(true, true)})
	res := byName(rep)
	want := map[string]bool{"banner": false, "rhythm": true, "pty": true, "style": true, "flags": true, "process": true, "network": true, "identity": true}
	for fam, w := range want {
		if rep.Coverage[fam] != w {
			t.Errorf("coverage[%s] = %v, want %v", fam, rep.Coverage[fam], w)
		}
	}
	if rep.ExitCode != ExitOK {
		var buf bytes.Buffer
		Render(rep, &buf)
		t.Errorf("exit = %d, want 0 (banner warn is optional)\n%s", rep.ExitCode, buf.String())
	}
	if r := res["sshd.loglevel"]; r.Status != StatusWarn || !r.Optional || !strings.Contains(r.Detail, "DEBUG1") {
		t.Errorf("sshd.loglevel = %+v", r)
	}
	if r := res["sshd.acceptenv"]; r.Status != StatusPass {
		t.Errorf("sshd.acceptenv = %+v", r)
	}
	if r := res["sshd.version"]; r.Status != StatusPass || !strings.Contains(r.Detail, "< 9.8") {
		t.Errorf("sshd.version = %+v", r)
	}
	if r := res["auditd.rules"]; r.Status != StatusPass || !strings.Contains(r.Detail, "whotyped") {
		t.Errorf("auditd.rules = %+v", r)
	}
	if r := res["sshlog"]; r.Status != StatusPass || !strings.Contains(r.Detail, "journalctl") {
		t.Errorf("sshlog = %+v", r)
	}
	if r := res["coverage.banner"]; !r.Optional || r.Status != StatusWarn {
		t.Errorf("coverage.banner = %+v", r)
	}
	if r := res["rules"]; r.Status != StatusPass {
		t.Errorf("rules = %+v", r)
	}
}

func TestRunProbeUsesSSHDT(t *testing.T) {
	// The RHEL fixture says INFO with no AI_AGENT, but `sshd -T` (root) says
	// VERBOSE + AI_AGENT; --probe must prefer the effective settings.
	fsys := fixtureFS(t, "rhel", map[string]string{
		"proc/1/status":  "Name:\tsystemd\n",
		"proc/1/environ": "PATH=/usr/bin\x00",
		"var/log/secure": "",
		"etc/ssh/sshrc":  SSHRC,
	})
	rep := Run(Options{Config: testConfig(t), FS: fsys, Exec: fakeExec(true, false), Probe: true})
	res := byName(rep)
	if r := res["sshd.effective"]; r.Status != StatusPass {
		t.Fatalf("sshd.effective = %+v", r)
	}
	if !rep.Coverage["rhythm"] || !rep.Coverage["identity"] {
		t.Errorf("coverage should follow sshd -T: %v", rep.Coverage)
	}
	if r := res["sshlog"]; r.Status != StatusPass || !strings.Contains(r.Detail, "auth log file") {
		t.Errorf("sshlog = %+v", r)
	}
}

func TestRunDegradedHost(t *testing.T) {
	// Not root, INFO, no AI_AGENT, auditd inactive, only a b64 rule.
	fsys := fixtureFS(t, "rhel", map[string]string{
		"proc/1/status":  "Name:\tsystemd\n",
		"var/log/secure": "",
	})
	rep := Run(Options{Config: testConfig(t), FS: fsys, Exec: fakeExec(false, false)})
	res := byName(rep)
	want := map[string]bool{"banner": false, "rhythm": false, "pty": false, "style": false, "flags": true, "process": true, "network": true, "identity": false}
	for fam, w := range want {
		if rep.Coverage[fam] != w {
			t.Errorf("coverage[%s] = %v, want %v", fam, rep.Coverage[fam], w)
		}
	}
	if rep.ExitCode != ExitDegraded {
		t.Errorf("exit = %d, want 1", rep.ExitCode)
	}
	if r := res["sshd.loglevel"]; r.Status != StatusWarn || r.Optional || !strings.Contains(r.Fix, "LogLevel VERBOSE") {
		t.Errorf("sshd.loglevel = %+v", r)
	}
	if r := res["sshd.acceptenv"]; r.Status != StatusWarn {
		t.Errorf("sshd.acceptenv = %+v", r)
	}
	if r := res["sshd.include"]; r.Status != StatusWarn {
		t.Errorf("sshd.include = %+v (RHEL fixture has no Include)", r)
	}
	if r := res["auditd.rules"]; r.Status != StatusWarn || !strings.Contains(r.Detail, "b64 only") {
		t.Errorf("auditd.rules = %+v", r)
	}
	if r := res["auditd.unit"]; r.Status != StatusWarn {
		t.Errorf("auditd.unit = %+v", r)
	}
	if r := res["procfs.environ"]; r.Status != StatusWarn {
		t.Errorf("procfs.environ = %+v", r)
	}
	if r := res["coverage.identity"]; !strings.Contains(r.Detail, "does not accept AI_AGENT") {
		t.Errorf("coverage.identity = %+v", r)
	}
}

func TestRunNoLogSourceCannotRun(t *testing.T) {
	fsys := fixtureFS(t, "ubuntu", map[string]string{"proc/1/status": "x"})
	rep := Run(Options{Config: testConfig(t), FS: fsys, Exec: fakeExec(true, false)})
	if rep.ExitCode != ExitCannotRun {
		t.Errorf("exit = %d, want 2 when neither journalctl nor an auth log exists", rep.ExitCode)
	}
	if r := byName(rep)["sshlog"]; r.Status != StatusFail {
		t.Errorf("sshlog = %+v", r)
	}
}

func TestRunInvalidConfigAndRules(t *testing.T) {
	cfg := testConfig(t)
	cfg.Scoring.Thresholds.Alert = 10
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("schema: whotyped.rules.v1\nstyles:\n  - id: style.x\n    regex: '('\n    weight: 5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Rules.Dirs = []string{dir}
	cfg.Allowlist.ProfilesEnabled = []string{"ansible", "nope"}
	rep := Run(Options{Config: cfg})
	res := byName(rep)
	if r := res["config"]; r.Status != StatusFail || !strings.Contains(r.Detail, "thresholds") {
		t.Errorf("config = %+v", r)
	}
	if r := res["rules"]; r.Status != StatusFail || !strings.Contains(r.Detail, "style.x") {
		t.Errorf("rules = %+v", r)
	}
	if rep.ExitCode != ExitCannotRun {
		t.Errorf("exit = %d", rep.ExitCode)
	}
}

func TestRunUnknownProfileWarns(t *testing.T) {
	cfg := testConfig(t)
	cfg.Allowlist.ProfilesEnabled = []string{"ansible", "nope"}
	rep := Run(Options{Config: cfg, FS: fstest.MapFS{}})
	if r := byName(rep)["rules.profiles"]; r.Status != StatusWarn || !strings.Contains(r.Detail, "nope") {
		t.Errorf("rules.profiles = %+v", r)
	}
	// The shipped ansible profile has no users/src_cidrs: an enabled profile
	// that matches any source is reported, and only enabled ones are.
	r := byName(rep)["rules.profiles.scope"]
	if r.Status != StatusWarn || !strings.Contains(r.Detail, "profile ansible matches any source; consider users/src_cidrs") {
		t.Errorf("rules.profiles.scope = %+v", r)
	}
	if strings.Contains(r.Detail, "vscode-remote") {
		t.Errorf("disabled profile reported: %s", r.Detail)
	}
	cfg.Allowlist.ProfilesEnabled = nil
	if r := byName(Run(Options{Config: cfg, FS: fstest.MapFS{}}))["rules.profiles.scope"]; r.Name != "" {
		t.Errorf("no profiles enabled but scope warning emitted: %+v", r)
	}
}

func TestRunWithoutPlatformProbes(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("on Linux the defaults probe the real host")
	}
	rep := Run(Options{Config: testConfig(t)})
	res := byName(rep)
	for _, name := range []string{"sshd.version", "sshd.config", "sshlog", "auditd", "procfs"} {
		if r := res[name]; r.Status != StatusSkip {
			t.Errorf("%s = %+v, want skip", name, r)
		}
	}
	for _, fam := range Families {
		if r := res["coverage."+fam]; r.Status != StatusSkip {
			t.Errorf("coverage.%s = %+v, want skip", fam, r)
		}
	}
	if rep.ExitCode != ExitOK {
		t.Errorf("exit = %d", rep.ExitCode)
	}
	results, code := Fix(Options{}, &bytes.Buffer{})
	if code != ExitCannotRun || len(results) != 1 || results[0].Status != StatusSkip {
		t.Errorf("Fix off Linux = %+v, %d", results, code)
	}
}

func TestMissingConfigFileIsDefaults(t *testing.T) {
	rep := Run(Options{ConfigPath: filepath.Join(t.TempDir(), "none.yaml"), FS: fstest.MapFS{}})
	r := byName(rep)["config"]
	if r.Status != StatusPass || !strings.Contains(r.Detail, "defaults") {
		t.Errorf("config = %+v", r)
	}
}

func TestRenderers(t *testing.T) {
	fsys := fixtureFS(t, "ubuntu", map[string]string{"proc/1/status": "x", "var/log/auth.log": ""})
	rep := Run(Options{Config: testConfig(t), FS: fsys, Exec: fakeExec(true, true)})
	var human bytes.Buffer
	Render(rep, &human)
	out := human.String()
	for _, want := range []string{"STATUS", "WARN*", "coverage:", "banner=no", "rhythm=yes", "fix:"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q:\n%s", want, out)
		}
	}
	var js bytes.Buffer
	if err := RenderJSON(rep, &js); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != len(rep.Results) || back.Coverage["rhythm"] != true {
		t.Errorf("json round trip lost data")
	}
}

// TestFixFilesMatchDeploy pins the Go constants to the canonical files.
func TestFixFilesMatchDeploy(t *testing.T) {
	cases := map[string]string{
		filepath.Join("..", "..", "deploy", "sshd", "90-whotyped.conf"):                       SSHDDropIn,
		filepath.Join("..", "..", "deploy", "audit.rules"):                                    AuditRules,
		filepath.Join("..", "..", "deploy", "sshd", "sshrc"):                                  SSHRC,
		filepath.Join("..", "..", "deploy", "ansible", "roles", "whotyped", "files", "sshrc"): SSHRC,
	}
	for path, want := range cases {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.ReplaceAll(string(data), "\r\n", "\n")
		if got != want {
			t.Errorf("%s differs from the embedded constant; update fixfiles.go", path)
		}
	}
	// The shipped rules must be recognised by our own parser.
	h64, h32, keys := ParseAuditRules(strings.NewReader(AuditRules))
	if !h64 || !h32 || len(keys) != 1 || keys[0] != "whotyped" {
		t.Errorf("ParseAuditRules(AuditRules) = %v %v %v", h64, h32, keys)
	}
	s := ParseSSHDConfig(strings.NewReader(SSHDDropIn))
	if !s.AcceptsAIAgent() || s.LogLevel != "VERBOSE" {
		t.Errorf("ParseSSHDConfig(SSHDDropIn) = %+v", s)
	}
}

func TestParseOpenSSHVersion(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		ok, atLeast  bool
	}{
		{"OpenSSH_8.9p1 Ubuntu-3ubuntu0.10, OpenSSL 3.0.2 15 Mar 2022", 8, 9, true, false},
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024", 9, 6, true, false},
		{"OpenSSH_9.8p1, OpenSSL 3.3.1 4 Jun 2024", 9, 8, true, true},
		{"OpenSSH_9.9p2 Debian-2, OpenSSL 3.4.0", 9, 9, true, true},
		{"OpenSSH_10.0p2 Ubuntu-1ubuntu1, OpenSSL 3.4.1", 10, 0, true, true},
		{"OpenSSH_10.5", 10, 5, true, true},
		{"sshd: unknown option -- V", 0, 0, false, false},
	}
	for _, c := range cases {
		major, minor, ok := parseOpenSSHVersion(c.in)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("parseOpenSSHVersion(%q) = %d.%d %v, want %d.%d %v", c.in, major, minor, ok, c.major, c.minor, c.ok)
		}
		if ok && versionAtLeast(major, minor, 9, 8) != c.atLeast {
			t.Errorf("%q: >= 9.8 = %v, want %v", c.in, !c.atLeast, c.atLeast)
		}
	}
}

// TestSSHDVersionTenIsNotLessThanNine runs the real check with a 10.x banner:
// the old string comparison reported OpenSSH 10.0 as "< 9.8".
func TestSSHDVersionTenIsNotLessThanNine(t *testing.T) {
	exec := func(name string, args ...string) (string, string, error) {
		if name == "sshd" && len(args) > 0 && args[0] == "-V" {
			return "", "OpenSSH_10.0p2 Ubuntu-1ubuntu1, OpenSSL 3.4.1 11 Feb 2025\n", nil
		}
		return "", "", errors.New("not found")
	}
	r := &runner{opts: Options{Exec: exec}}
	r.checkSSHDVersion()
	if len(r.results) != 1 {
		t.Fatalf("results %+v", r.results)
	}
	got := r.results[0]
	if got.Status != StatusPass || !strings.Contains(got.Detail, ">= 9.8") || strings.Contains(got.Detail, "< 9.8") {
		t.Errorf("sshd.version = %+v", got)
	}
}

func TestSSHRCHookDecidesIdentityCoverage(t *testing.T) {
	base := map[string]string{
		"proc/1/status":           "Name:\tsystemd\n",
		"proc/1/environ":          "PATH=/usr/bin\x00",
		"var/log/audit/audit.log": "",
	}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// The ubuntu fixture ships the hook: identity is live.
	rep := Run(Options{Config: testConfig(t), FS: fixtureFS(t, "ubuntu", base), Exec: fakeExec(true, true)})
	if r := byName(rep)["sshd.sshrc"]; r.Status != StatusPass || !rep.Coverage["identity"] {
		t.Fatalf("hook present: sshd.sshrc=%+v identity=%v", r, rep.Coverage["identity"])
	}

	// An operator's own sshrc without the hook: warn, point at the block,
	// identity not live, and --fix must not claim it will overwrite it.
	rep = Run(Options{Config: testConfig(t), FS: fixtureFS(t, "ubuntu", with(map[string]string{"etc/ssh/sshrc": "xauth stuff\n"})), Exec: fakeExec(true, true)})
	r := byName(rep)["sshd.sshrc"]
	if r.Status != StatusWarn || !strings.Contains(r.Fix, "never edits") || rep.Coverage["identity"] {
		t.Fatalf("foreign sshrc: %+v identity=%v", r, rep.Coverage["identity"])
	}
	if !strings.Contains(byName(rep)["coverage.identity"].Detail, "one-command-per-step") {
		t.Errorf("coverage.identity detail = %q", byName(rep)["coverage.identity"].Detail)
	}
}

func TestLogContentWarnsOnSilentAuthLog(t *testing.T) {
	cfg := testConfig(t)
	cfg.Readers.SSHLog.Source = "file"
	cfg.Readers.SSHLog.File = "/var/log/auth.log"
	files := map[string]string{"proc/1/status": "Name:\tsystemd\n", "etc/ssh/sshrc": SSHRC}

	files["var/log/auth.log"] = "2026-09-14T06:00:02.257655+00:00 lab CRON[12]: (root) CMD (true)\n"
	rep := Run(Options{Config: cfg, FS: fixtureFS(t, "ubuntu", files), Exec: fakeExec(true, true)})
	if r := byName(rep)["sshlog.content"]; r.Status != StatusWarn || !strings.Contains(r.Fix, "writable by the syslog daemon") {
		t.Fatalf("silent auth.log: %+v", r)
	}

	files["var/log/auth.log"] = "2026-09-14T06:00:08.373565+00:00 lab sshd[59]: Accepted publickey for alice from 127.0.0.1 port 44324 ssh2: ED25519 SHA256:x\n"
	rep = Run(Options{Config: cfg, FS: fixtureFS(t, "ubuntu", files), Exec: fakeExec(true, true)})
	if r := byName(rep)["sshlog.content"]; r.Status != StatusPass {
		t.Fatalf("auth.log with sshd lines: %+v", r)
	}
}
