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
	want := map[string]bool{"banner": false, "rhythm": false, "pty": false, "style": true, "flags": true, "process": true, "network": true, "identity": false}
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
		filepath.Join("..", "..", "deploy", "sshd", "90-whotyped.conf"): SSHDDropIn,
		filepath.Join("..", "..", "deploy", "audit.rules"):              AuditRules,
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
