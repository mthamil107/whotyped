package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustLoad(t *testing.T, dirs ...string) *Pack {
	t.Helper()
	p, err := Load(dirs...)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedPackLoadsAndValidates(t *testing.T) {
	p := mustLoad(t)
	if errs := Validate(p); len(errs) != 0 {
		for _, e := range errs {
			t.Error(e)
		}
	}
	if p.Version != "2026.09.11" {
		t.Errorf("version = %q", p.Version)
	}
	want := []string{"claude-code", "codex-cli", "gemini-cli", "cursor-cli", "cursor-ide", "aider", "opencode", "goose",
		"amazon-q-cli", "kiro-cli", "copilot-cli", "cline", "augment-cli", "antigravity", "junie", "devin", "warp",
		"openclaw", "kimi", "grok"}
	for _, id := range want {
		if p.AgentByID(id) == nil {
			t.Errorf("agent %q missing", id)
		}
	}
	if len(p.Styles) != 10 {
		t.Errorf("styles = %d, want 10", len(p.Styles))
	}
	if len(p.Profiles) != 9 {
		t.Errorf("profiles = %d, want 9", len(p.Profiles))
	}
	// Entries shipped with disabled: true are removed, not carried.
	if p.HostMatch("oauth2.googleapis.com", 443) != nil {
		t.Error("disabled oauth2 host should be removed from the merged pack")
	}
	if p.HostMatchIP("127.0.0.1", 11434) != nil {
		t.Error("disabled ollama entry should be removed from the merged pack")
	}
}

func TestOverrideDirMerge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "10-override.yaml", `
schema: whotyped.rules.v1
version: "2026.09.12"
agents:
  - id: claude-code
    display: Claude Code (site build)
    process_names: [claude, claude-site]
  - id: acme-bot
    display: Acme Bot
    env_ai_agent: [acme]
banners:
  - id: putty
    disabled: true
styles:
  - id: style.acme
    regex: 'acme-run'
    weight: 3
api_hosts:
  - host: llm.acme.internal
    agent: acme-bot
    port: 8443
`)
	writeFile(t, dir, "20-profiles.yml", `
schema: whotyped.allowlist.v1
profiles:
  - id: rsync-backup
    disabled: true
  - id: acme-deploy
    description: Acme deploy bot
    match:
      src_cidrs: ["10.1.0.0/16"]
      any_of:
        - cmd_regex: '^/opt/acme/deploy'
    suppress: [rhythm, pty.none, style.acme]
`)
	writeFile(t, dir, "README.txt", "ignored")

	p := mustLoad(t, dir, filepath.Join(dir, "does-not-exist"))
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("validate: %v", errs)
	}
	if p.Version != "2026.09.12" {
		t.Errorf("version = %q, want override version", p.Version)
	}
	a := p.AgentByID("claude-code")
	if a == nil || a.Display != "Claude Code (site build)" {
		t.Fatalf("override did not replace claude-code: %+v", a)
	}
	// Later wins means whole-entry replacement: fields not restated are gone.
	if len(a.EnvVars) != 0 {
		t.Errorf("replaced entry kept env_vars from the default: %v", a.EnvVars)
	}
	if p.Agents[0].ID != "claude-code" {
		t.Errorf("replacement must keep position; got %q first", p.Agents[0].ID)
	}
	if p.AgentForAIAgentValue("ACME@1.0") != "acme-bot" {
		t.Error("new agent not reachable via AI_AGENT value")
	}
	if k, id, _ := p.BannerKind("PuTTY_Release_0.81"); k != "" || id != "" {
		t.Errorf("disabled banner still matches: %s/%s", k, id)
	}
	if h := p.HostMatch("LLM.acme.internal", 8443); h == nil || h.Agent != "acme-bot" {
		t.Errorf("added host not found: %+v", h)
	}
	if p.ProfileByID("rsync-backup") != nil {
		t.Error("disabled profile not removed")
	}
	if p.ProfileByID("acme-deploy") == nil {
		t.Error("added profile missing")
	}
}

func TestBadRegexReported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", `
schema: whotyped.rules.v1
banners:
  - id: broken
    regex: '^(unclosed'
    kind: library
styles:
  - id: style.heavy
    regex: 'x'
    weight: 99
  - id: nostyleprefix
    regex: 'y'
    weight: 5
api_hosts:
  - host: Upper.Case.Example
  - cidr: 300.1.1.1/40
`)
	p := mustLoad(t, dir)
	errs := Validate(p)
	joined := make([]string, 0, len(errs))
	for _, e := range errs {
		joined = append(joined, e.Error())
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		`banner "broken": regex`,
		`style "style.heavy": weight 99`,
		`style "nostyleprefix": id must`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing error containing %q in:\n%s", want, all)
		}
	}
	if !strings.Contains(all, "300.1.1.1/40") {
		t.Errorf("bad cidr not reported:\n%s", all)
	}
	// Load lower-cases host names, so the mixed-case entry is valid afterwards.
	if p.HostMatch("upper.case.example", 443) == nil {
		t.Error("mixed-case host should be normalised, not dropped")
	}
	if strings.Contains(all, "upper.case.example") {
		t.Errorf("normalised host wrongly reported:\n%s", all)
	}
}

func TestParseFileRejectsUnknownKeysAndSchema(t *testing.T) {
	if _, err := ParseFile("x", []byte("schema: whotyped.rules.v1\nagents:\n  - id: a\n    display: A\n    proces_names: [a]\n")); err == nil {
		t.Error("typo in key accepted")
	}
	if _, err := ParseFile("x", []byte("schema: whotyped.rules.v9\n")); err == nil {
		t.Error("unknown schema accepted")
	}
	if _, err := ParseFile("x", []byte("agents: []\n")); err == nil {
		t.Error("missing schema accepted")
	}
	if _, err := ParseFile("x", []byte("")); err == nil {
		t.Error("empty file accepted")
	}
}

func TestProfileSuppressValidation(t *testing.T) {
	p := mustLoad(t)
	p.Profiles = append(p.Profiles, Profile{
		ID:       "bad",
		Match:    Match{AnyOf: []MatchClause{{CmdRegex: "x"}}},
		Suppress: []string{"process", "proc.skip_flags", "env.ai_agent", "nonsense", "banner.automation", "style"},
	})
	errs := Validate(p)
	got := map[string]bool{}
	for _, e := range errs {
		got[e.Error()] = true
	}
	for _, want := range []string{
		`profile "bad": suppress "process" requires allow_agent_processes: true`,
		`profile "bad": suppress "proc.skip_flags" requires allow_agent_processes: true`,
		`profile "bad": suppress "env.ai_agent" requires allow_agent_processes: true`,
		`profile "bad": suppress "nonsense" is not a known clue id or category`,
	} {
		if !got[want] {
			t.Errorf("missing %q; got %v", want, errs)
		}
	}
	if len(errs) != 4 {
		t.Errorf("want exactly 4 errors, got %d: %v", len(errs), errs)
	}
	p.Profiles[len(p.Profiles)-1].AllowAgentProcesses = true
	p.Profiles[len(p.Profiles)-1].Suppress = []string{"process", "proc.skip_flags", "env.ai_agent", "rhythm", "style.pager_guard", "style.heredoc"}
	if errs := Validate(p); len(errs) != 0 {
		t.Errorf("allow_agent_processes should permit protected suppression: %v", errs)
	}
}

func TestAgentForAIAgentValue(t *testing.T) {
	p := mustLoad(t)
	cases := map[string]string{
		"claude-code":        "claude-code",
		"Claude-Code@2.0.1":  "claude-code",
		"cursor-cli":         "cursor-cli",
		"CURSOR":             "cursor-ide",
		"codex_cli":          "codex-cli",
		"github-copilot":     "copilot-cli",
		"amazon-q-cli@1.2.3": "amazon-q-cli",
		"kiro-cli":           "kiro-cli", // resolves via env_ai_agent, also the id
		"unknown-thing":      "",
		"":                   "",
		"@1.0":               "",
	}
	for in, want := range cases {
		if got := p.AgentForAIAgentValue(in); got != want {
			t.Errorf("AgentForAIAgentValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBannerKind(t *testing.T) {
	p := mustLoad(t)
	cases := []struct{ banner, kind, id string }{
		{"SSH-2.0-paramiko_3.4.0", "library", "paramiko"},
		{"paramiko_3.4.0", "library", "paramiko"}, // sshd log form, prefix dropped
		{"SSH-2.0-AsyncSSH_2.14.2", "library", "asyncssh"},
		{"SSH-2.0-ssh2js1.17.0", "library", "ssh2js"},
		{"SSH-2.0-Go", "library", "go"},
		{"Go", "library", "go"},
		{"SSH-2.0-Golang-Thing", "", ""},
		{"SSH-2.0-russh_0.45.0", "library", "russh"},
		{"SSH-2.0-libssh_0.10.6", "library", "libssh"},
		{"SSH-2.0-libssh2_1.11.0", "library", "libssh2"},
		{"SSH-2.0-JSCH_0.2.17", "library", "jsch"},
		{"SSH-2.0-JSCH-0.1.55", "library", "jsch"},
		{"SSH-2.0-SSHJ_0.38.0", "library", "sshj"},
		{"SSH-2.0-dropbear_2022.83", "human", "dropbear"},
		{"OpenSSH_9.9p1 Ubuntu-3ubuntu3", "human", "openssh"},
		{"SSH-2.0-OpenSSH_for_Windows_9.5", "human", "openssh"},
		{"SSH-2.0-PuTTY_Release_0.81", "human", "putty"},
		{"SSH-2.0-WinSCP_release_6.3.4", "human", "winscp"},
		{"SSH-2.0-9.31 FlowSsh: Bitvise SSH Client 9.31", "human", "bitvise"},
		{"SSH-2.0-APACHE-SSHD-2.12.0", "automation", "mina-sshd"},
		{"", "", ""},
	}
	for _, c := range cases {
		kind, id, _ := p.BannerKind(c.banner)
		if kind != c.kind || id != c.id {
			t.Errorf("BannerKind(%q) = %s/%s, want %s/%s", c.banner, kind, id, c.kind, c.id)
		}
	}
}

// TestStyleRegexes pins the RE2 patterns against agent-shaped and
// human-shaped commands. Each case lists the style ids that must fire and
// implicitly asserts that the others do not, except the noisy shared ones
// listed in ignore.
func TestStyleRegexes(t *testing.T) {
	p := mustLoad(t)
	cases := []struct {
		cmd  string
		want []string
	}{
		{`git commit -m "$(cat <<'EOF'
Fix the thing
EOF
)"`, []string{"style.heredoc"}},
		{`cat > /tmp/x.py <<EOF`, []string{"style.heredoc"}},
		{`cat <<- "END" > f`, []string{"style.heredoc"}},
		{`grep foo <<< "$var"`, nil},
		{`cd /srv/app && git pull && npm ci && systemctl restart app`, []string{"style.compound"}},
		{`cd /srv/app; ls -la | head -20`, []string{"style.compound", "style.head"}},
		{`cd /srv/app; ls`, nil}, // one operator only
		{`cd /srv/app && make`, nil},
		{`bash -lc 'ls -la /srv/app'`, []string{"style.tool_wrapper"}},
		{`sh -c "id"`, []string{"style.tool_wrapper"}},
		{`/bin/bash -l -c 'whoami'`, []string{"style.tool_wrapper"}},
		{`timeout 30 sh -c 'uptime'`, []string{"style.tool_wrapper", "style.timeout"}},
		{`ssh -c aes256-ctr host`, nil},
		{`bash deploy.sh`, nil},
		{`git --no-pager log -n 5`, []string{"style.nopager"}},
		{`git -P diff`, []string{"style.nopager"}},
		{`PAGER=cat git log`, []string{"style.nopager"}},
		{`GIT_PAGER=cat git log`, []string{"style.nopager"}},
		{`journalctl -u sshd | head -n 50`, []string{"style.head"}},
		{`journalctl -u sshd | head -50`, []string{"style.head"}},
		{`journalctl -u sshd | head`, nil},
		{`tail -f /var/log/syslog`, nil},
		{`dmesg | tail -n 100`, []string{"style.tail"}},
		{`dmesg | tail -n +5`, []string{"style.tail"}},
		{`sed -n '120,160p' /etc/ssh/sshd_config`, []string{"style.sed_range"}},
		{`sed -n 1,\$p f`, nil},
		{`sed -n '1,$p' f`, []string{"style.sed_range"}},
		{`sed -i s/a/b/ f`, nil},
		{`make 2>&1`, []string{"style.stderr_merge"}},
		{`timeout 120s bash -c 'make'`, []string{"style.timeout", "style.tool_wrapper"}},
		{`timeout -k 5 30 ./run`, []string{"style.timeout"}},
		{`echo timeout`, nil},
		{`ls -la /home/deploy/app/config /home/deploy/app/logs`, []string{"style.abs_paths"}},
		{`/usr/bin/python3 /opt/app/main.py`, []string{"style.abs_paths"}},
		{`cat /etc/hosts`, nil},
		{`curl https://example.com/a/b https://example.com/c/d`, nil},
		{`ls`, nil},
	}
	for _, c := range cases {
		got := map[string]bool{}
		for _, m := range p.StyleMatches(c.cmd) {
			got[m.Style.ID] = true
		}
		for _, id := range c.want {
			if !got[id] {
				t.Errorf("%q: expected %s to match", c.cmd, id)
			}
			delete(got, id)
		}
		for id := range got {
			t.Errorf("%q: unexpected match %s", c.cmd, id)
		}
	}
}

func TestHostMatch(t *testing.T) {
	p := mustLoad(t)
	if h := p.HostMatch("api.anthropic.com", 0); h == nil || h.Agent != "claude-code" {
		t.Errorf("api.anthropic.com: %+v", h)
	}
	if h := p.HostMatch("API.OpenAI.com.", 443); h == nil || h.Vendor != "OpenAI" {
		t.Errorf("case/trailing dot: %+v", h)
	}
	if h := p.HostMatch("myres.openai.azure.com", 443); h == nil || h.Vendor != "Microsoft" {
		t.Errorf("azure wildcard: %+v", h)
	}
	if h := p.HostMatch("bedrock-runtime.eu-west-1.amazonaws.com", 443); h == nil || h.Vendor != "Amazon" {
		t.Errorf("bedrock wildcard: %+v", h)
	}
	if h := p.HostMatch("api.anthropic.com", 8080); h != nil {
		t.Errorf("port mismatch should not match: %+v", h)
	}
	if h := p.HostMatch("example.com", 443); h != nil {
		t.Errorf("unknown host matched: %+v", h)
	}
	if h := p.HostMatch("evil.api.anthropic.com", 443); h != nil {
		t.Errorf("subdomain of exact host must not match: %+v", h)
	}
}

func TestLoadDirsWithoutDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "schema: whotyped.rules.v1\nagents:\n  - id: x\n    display: X\n")
	p, err := LoadDirs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Agents) != 1 || len(p.Banners) != 0 {
		t.Errorf("LoadDirs merged defaults: %d agents, %d banners", len(p.Agents), len(p.Banners))
	}
	if _, err := LoadDirs(filepath.Join(dir, "a.yaml")); err == nil {
		t.Error("a file path should not be accepted as a dir")
	}
}
