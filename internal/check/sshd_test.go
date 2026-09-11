package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseSSHDConfigFSWithIncludeAndMatch(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "ubuntu"))
	s, err := ParseSSHDConfigFS(fsys, "etc/ssh/sshd_config")
	if err != nil {
		t.Fatal(err)
	}
	// The Include sits above `LogLevel INFO`, so the drop-in's VERBOSE wins.
	if s.LogLevel != "VERBOSE" {
		t.Errorf("LogLevel = %q, want VERBOSE (first occurrence, via Include)", s.LogLevel)
	}
	if !s.AcceptsAIAgent() {
		t.Errorf("AI_AGENT not accepted; AcceptEnv = %v", s.AcceptEnv)
	}
	if !s.AcceptsEnv("LC_ALL") || s.AcceptsEnv("HOME") {
		t.Errorf("wildcard handling wrong: %v", s.AcceptEnv)
	}
	// Match-scoped settings must not leak into the global view.
	if s.AcceptsEnv("BACKUP_JOB") || s.PermitUserEnvironment != "" {
		t.Errorf("Match block leaked: %+v", s)
	}
	if !s.MatchSeen {
		t.Error("MatchSeen should be true")
	}
	if len(s.Files) != 3 || !strings.HasSuffix(s.Files[1], "50-cloud-init.conf") || !strings.HasSuffix(s.Files[2], "90-whotyped.conf") {
		t.Errorf("Files = %v (want main + two drop-ins in sorted order)", s.Files)
	}
	if len(s.Unresolved) != 0 || len(s.Includes) != 1 {
		t.Errorf("Includes = %v, Unresolved = %v", s.Includes, s.Unresolved)
	}
}

func TestParseSSHDConfigNoFS(t *testing.T) {
	src := `
# comment
include /etc/ssh/sshd_config.d/*.conf
LOGLEVEL debug1
loglevel INFO
AcceptEnv=LANG
AcceptEnv "AI_AGENT" FOO_*
PermitUserEnvironment yes
Match Address 10.0.0.0/8
   LogLevel QUIET
   AcceptEnv NOPE
Match all
   AcceptEnv AFTER_MATCH_ALL
`
	s := ParseSSHDConfig(strings.NewReader(src))
	if s.LogLevel != "DEBUG1" || !s.AtLeastDebug1() || !s.AtLeastVerbose() {
		t.Errorf("LogLevel = %q", s.LogLevel)
	}
	if !s.AcceptsAIAgent() || !s.AcceptsEnv("FOO_BAR") || s.AcceptsEnv("NOPE") {
		t.Errorf("AcceptEnv = %v", s.AcceptEnv)
	}
	if !s.AcceptsEnv("AFTER_MATCH_ALL") {
		t.Error("`Match all` should return to the global section")
	}
	if s.PermitUserEnvironment != "yes" {
		t.Errorf("PermitUserEnvironment = %q", s.PermitUserEnvironment)
	}
	if len(s.Unresolved) != 1 {
		t.Errorf("Include without FS should be unresolved: %v", s.Unresolved)
	}
	empty := ParseSSHDConfig(strings.NewReader(""))
	if empty.EffectiveLogLevel() != "INFO" || empty.AtLeastVerbose() || empty.AcceptsAIAgent() {
		t.Errorf("defaults: %+v", empty)
	}
}

func TestParseSSHDConfigIncludeInsideMatchAndRelative(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/ssh/sshd_config":          {Data: []byte("Include sshd_config.d/*.conf\nMatch User x\nInclude /etc/ssh/match.d/*.conf\n")},
		"etc/ssh/sshd_config.d/a.conf": {Data: []byte("LogLevel VERBOSE\n")},
		"etc/ssh/match.d/m.conf":       {Data: []byte("LogLevel DEBUG3\nAcceptEnv AI_AGENT\n")},
	}
	s, err := ParseSSHDConfigFS(fsys, "etc/ssh/sshd_config")
	if err != nil {
		t.Fatal(err)
	}
	if s.LogLevel != "VERBOSE" {
		t.Errorf("relative Include not resolved against /etc/ssh: LogLevel = %q", s.LogLevel)
	}
	if s.AcceptsAIAgent() {
		t.Error("Include inside a Match block must not contribute global settings")
	}
	if len(s.Includes) != 2 {
		t.Errorf("Includes = %v", s.Includes)
	}
}

func TestParseSSHDConfigTOutput(t *testing.T) {
	out := "port 22\naddressfamily any\nloglevel VERBOSE\nacceptenv LANG\nacceptenv LC_*\nacceptenv AI_AGENT\npermituserenvironment no\n"
	s := ParseSSHDConfig(strings.NewReader(out))
	if s.LogLevel != "VERBOSE" || !s.AcceptsAIAgent() || s.PermitUserEnvironment != "no" {
		t.Errorf("sshd -T parse: %+v", s)
	}
}

func TestParseSSHDConfigMissingFile(t *testing.T) {
	if _, err := ParseSSHDConfigFS(fstest.MapFS{}, "etc/ssh/sshd_config"); err == nil {
		t.Error("missing main file should be an error")
	}
}

func TestParseAuditRules(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "ubuntu"))
	f, err := fsys.Open("etc/audit/rules.d/90-whotyped.rules")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h64, h32, keys := ParseAuditRules(f)
	if !h64 || !h32 || strings.Join(keys, ",") != "whotyped" {
		t.Errorf("ubuntu fixture: %v %v %v", h64, h32, keys)
	}

	rhel, err := os.DirFS(filepath.Join("testdata", "rhel")).Open("etc/audit/rules.d/audit.rules")
	if err != nil {
		t.Fatal(err)
	}
	defer rhel.Close()
	h64, h32, keys = ParseAuditRules(rhel)
	if !h64 || h32 || strings.Join(keys, ",") != "exec64" {
		t.Errorf("rhel fixture: %v %v %v (watch rule key must not count)", h64, h32, keys)
	}

	cases := []struct {
		src      string
		h64, h32 bool
		keys     string
	}{
		{"-a always,exit -F arch=b64 -S execve,execveat -k a -k b", true, false, "a,b"},
		{"-a never,exit -F arch=b64 -S execve -k x", false, false, ""},
		{"-a always,exit -F arch=b64 -S openat -k x", false, false, ""},
		{"-a always,exit -S execve -k native", true, false, "native"},
		{"-A always,exit -F arch=b32 -S all -k everything", false, true, "everything"},
		{"-a always,exit -F arch=b64 -S 59 -F auid>=1000", true, false, ""},
		{"# -a always,exit -F arch=b64 -S execve -k commented", false, false, ""},
		{"", false, false, ""},
	}
	for _, c := range cases {
		h64, h32, keys := ParseAuditRules(strings.NewReader(c.src))
		if h64 != c.h64 || h32 != c.h32 || strings.Join(keys, ",") != c.keys {
			t.Errorf("%q: %v %v %v", c.src, h64, h32, keys)
		}
	}
}
