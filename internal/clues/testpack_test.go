package clues

import (
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

var t0 = time.Date(2026, 9, 11, 13, 50, 0, 0, time.UTC)

func at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

// testPack mirrors the shape of rules/*.yaml closely enough for the detectors.
// The rules loader is owned by another engineer; this literal is the contract
// the detectors are written against.
func testPack() *rules.Pack {
	return &rules.Pack{
		Version: "test",
		Agents: []rules.Agent{
			{ID: "claude-code", Display: "Claude Code", Vendor: "Anthropic",
				ProcessNames: []string{"claude"}, ArgvContains: []string{"@anthropic-ai/claude-code"},
				EnvVars:    []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_IS_COWORK"},
				EnvAIAgent: []string{"claude-code", "claude"},
				SkipFlags:  []string{"--dangerously-skip-permissions", "--permission-mode bypassPermissions"},
				APIHosts:   []string{"api.anthropic.com"}},
			{ID: "codex", Display: "Codex CLI", Vendor: "OpenAI",
				ProcessNames: []string{"codex", "codex-linux-sandbox"},
				EnvVars:      []string{"CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED=1", "CODEX_THREAD_ID"},
				SkipFlags:    []string{"--full-auto", "--dangerously-bypass-approvals-and-sandbox", "--yolo"}},
			{ID: "gemini-cli", Display: "Gemini CLI", Vendor: "Google",
				ProcessNames: []string{"gemini"}, EnvVars: []string{"GEMINI_CLI"},
				SkipFlags: []string{"--yolo", "--approval-mode=yolo"}},
			{ID: "cursor", Display: "Cursor", ProcessNames: []string{"cursor-agent"},
				EnvVars: []string{"CURSOR_AGENT", "CURSOR_EXTENSION_HOST_ROLE=agent-exec"}, SkipFlags: []string{"--force", "--yolo"}},
			{ID: "aider", Display: "Aider", ProcessNames: []string{"aider"}, SkipFlags: []string{"--yes-always"}},
			{ID: "goose", Display: "Goose", ProcessNames: []string{"goose"}, EnvVars: []string{"GOOSE_TERMINAL", "AGENT=goose"}},
			{ID: "amazon-q", Display: "Amazon Q CLI", ProcessNames: []string{"q", "qchat", "qterm"},
				EnvVars: []string{"Q_TERM"}, SkipFlags: []string{"--trust-all-tools"}},
			{ID: "copilot-cli", Display: "Copilot CLI", ProcessNames: []string{"copilot"},
				EnvVars: []string{"COPILOT_MODEL", "COPILOT_ALLOW_ALL"}, SkipFlags: []string{"--allow-all-tools", "--allow-all"}},
			{ID: "disabled-tool", ProcessNames: []string{"vim"}, Disabled: true},
		},
		Banners: []rules.Banner{
			{ID: "paramiko", Regex: `paramiko_`, Kind: "library"},
			{ID: "asyncssh", Regex: `AsyncSSH_`, Kind: "library"},
			{ID: "ssh2js", Regex: `ssh2js`, Kind: "library"},
			{ID: "go", Regex: `^SSH-2\.0-Go(\s|$)`, Kind: "library"},
			{ID: "russh", Regex: `russh_`, Kind: "library"},
			{ID: "libssh", Regex: `libssh2?_`, Kind: "library"},
			{ID: "terraform", Regex: `terraform`, Kind: "automation"},
			{ID: "openssh", Regex: `OpenSSH_`, Kind: "human"},
			{ID: "putty", Regex: `PuTTY`, Kind: "human"},
		},
		Styles: []rules.Style{
			{ID: "heredoc", Regex: `<<-?\s*['"]?EOF`, Weight: 10},
			{ID: "compound", Regex: `^cd \S+ &&`, Weight: 10},
			{ID: "tool_wrapper", Regex: `^(/usr)?(/bin/)?(ba)?sh -l?c `, Weight: 8},
			{ID: "pager_guard_no_pager", Regex: `--no-pager`, Weight: 5, Group: "pager_guard"},
			{ID: "pager_guard_head", Regex: `\| *head -n`, Weight: 5, Group: "pager_guard"},
			{ID: "pager_guard_tail", Regex: `\| *tail -n`, Weight: 5, Group: "pager_guard"},
			{ID: "pager_guard_sed", Regex: `sed -n '?\d+,\d+p`, Weight: 5, Group: "pager_guard"},
			{ID: "pager_guard_stderr", Regex: `2>&1`, Weight: 5, Group: "pager_guard"},
			{ID: "pager_guard_timeout", Regex: `^timeout \d+`, Weight: 5, Group: "pager_guard"},
		},
		APIHosts: []rules.Host{
			{Host: "api.anthropic.com", Agent: "claude-code", Vendor: "Anthropic"},
			{Host: "api.openai.com", Agent: "codex", Vendor: "OpenAI"},
			{Host: "generativelanguage.googleapis.com", Agent: "gemini-cli"},
			{Host: "openrouter.ai"},
			{CIDR: "160.79.104.0/23", Agent: "claude-code", Notes: "Anthropic egress (test)"},
			{Host: "127.0.0.1", Port: 11434, Vendor: "Ollama"},
		},
		Profiles: []rules.Profile{
			{ID: "ansible", Match: rules.Match{
				AnyOf: []rules.MatchClause{
					{CmdRegex: `AnsiballZ_|\.ansible/tmp/|echo ~\w* && sleep 0`},
					{BannerRegex: `paramiko_`},
				}, MinMatchRatio: 0.8},
				Suppress: []string{"banner", "rhythm", "pty", "style"}, MaxScore: 20},
			{ID: "vscode-remote", Match: rules.Match{
				AnyOf: []rules.MatchClause{
					{CmdRegex: `\.vscode-server/|server-main\.js|code-server`},
					{CmdRegex: `git -c core\.quotepath=false`},
				}, MinMatchRatio: 0.7},
				Suppress: []string{"rhythm", "style", "pty.none"}, MaxScore: 30},
			{ID: "github-runner", Match: rules.Match{
				Users: []string{"runner"}, SrcCIDRs: []string{"10.200.0.0/16"},
				AnyOf: []rules.MatchClause{{PathRegex: `^/home/runner/work/`}}},
				Suppress: []string{"rhythm", "style", "pty", "banner"}, MaxScore: 10},
		},
	}
}

// mkTrack builds a Track with one open connection.
func mkTrack(user, ip string) *session.Track {
	c := &session.Connection{ID: "cn_1", User: user, SrcIP: ip, SrcPort: 51234, SSHDPID: 4410, Opened: at(0)}
	return &session.Track{ID: "tr_test", Key: session.TrackKey{User: user, Fingerprint: "SHA256:abc", SrcIP: ip},
		Connections: []*session.Connection{c}, FirstSeen: at(0), LastSeen: at(0), Mode: "remote_agent"}
}

// addExecChannels appends n sshlog exec channels every gap seconds starting at start.
func addExecChannels(t *session.Track, n int, start, gap float64) {
	for i := 0; i < n; i++ {
		ts := at(start + float64(i)*gap)
		t.Connections[0].ExecCount++
		t.Execs = append(t.Execs, session.ExecSample{TS: ts, PID: 4410, Origin: "sshlog"})
	}
}

// addCmds appends auditd execve samples 5 s apart.
func addCmds(t *session.Track, cmds ...string) {
	for i, c := range cmds {
		argv0 := c
		for j := 0; j < len(c); j++ {
			if c[j] == ' ' {
				argv0 = c[:j]
				break
			}
		}
		t.Execs = append(t.Execs, session.ExecSample{TS: at(100 + float64(i)*5), Argv0: argv0, Cmd: c, Origin: "auditd", Ses: 7})
	}
}

func ids(cs []Clue) map[string]int {
	m := map[string]int{}
	for _, c := range cs {
		m[c.ID] = c.Weight
	}
	return m
}
