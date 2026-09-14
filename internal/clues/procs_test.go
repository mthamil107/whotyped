package clues

import (
	"strings"
	"testing"

	"github.com/mthamil107/whotyped/internal/session"
)

func TestProcsDetector(t *testing.T) {
	cases := []struct {
		name  string
		procs []session.ProcSample
		want  map[string]int
		ev    string
		agent string // IdentifyAgent result
	}{
		{"none", nil, map[string]int{}, "", ""},
		{"human-shell", []session.ProcSample{{PID: 1, Comm: "bash", Exe: "/usr/bin/bash", Cmd: "-bash"}}, map[string]int{}, "", ""},
		{"claude-by-comm", []session.ProcSample{{PID: 4411, Comm: "claude", Exe: "/usr/local/bin/claude", Cmd: "claude"}},
			map[string]int{"proc.agent_name": 45}, "claude (pid 4411) claude-code", "claude-code"},
		{"node-by-argv", []session.ProcSample{{PID: 12, Comm: "node", Exe: "/usr/bin/node", Cmd: "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}},
			map[string]int{"proc.agent_name": 45}, "node (pid 12) claude-code", "claude-code"},
		{"child-env", []session.ProcSample{{PID: 4412, Comm: "bash", Cmd: "bash -c git status", Env: map[string]string{"CLAUDECODE": "1"}}},
			map[string]int{"proc.agent_env": 40}, "bash (pid 4412) CLAUDECODE=1", "claude-code"},
		{"env-name-equals-value-match", []session.ProcSample{{PID: 5, Comm: "sh", Env: map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "1"}}},
			map[string]int{"proc.agent_env": 40}, "CODEX_SANDBOX_NETWORK_DISABLED=1", "codex"},
		{"env-name-equals-value-mismatch", []session.ProcSample{{PID: 5, Comm: "sh", Env: map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "0"}}},
			map[string]int{}, "", ""},
		{"skip-flag-from-reader", []session.ProcSample{{PID: 4411, Comm: "claude", Cmd: "claude --dangerously-skip-permissions -p fix it",
			Flags: []string{"--dangerously-skip-permissions"}}},
			map[string]int{"proc.agent_name": 45, "proc.skip_flags": 25}, "claude (pid 4411) --dangerously-skip-permissions", "claude-code"},
		{"skip-flag-from-cmd", []session.ProcSample{{PID: 9, Comm: "gemini", Cmd: "gemini --yolo -p do it"}},
			map[string]int{"proc.agent_name": 45, "proc.skip_flags": 25}, "gemini (pid 9) --yolo", "gemini-cli"},
		{"reader-prematched-agent-not-in-pack", []session.ProcSample{{PID: 3, Comm: "kiro-cli", Agent: "kiro"}},
			map[string]int{"proc.agent_name": 45}, "kiro-cli (pid 3) kiro", "kiro"},
		{"disabled-rule", []session.ProcSample{{PID: 3, Comm: "vim"}}, map[string]int{}, "", ""},
		{"all-three-categories", []session.ProcSample{
			{PID: 1, Comm: "codex", Cmd: "codex --full-auto"},
			{PID: 2, Comm: "bash", Env: map[string]string{"CODEX_SANDBOX": "1"}},
		}, map[string]int{"proc.agent_name": 45, "proc.agent_env": 40, "proc.skip_flags": 25}, "codex (pid 1) --full-auto", "codex"},
		{"evidence-capped", []session.ProcSample{
			{PID: 1, Comm: "aider"}, {PID: 2, Comm: "aider"}, {PID: 3, Comm: "aider"}, {PID: 4, Comm: "aider"}, {PID: 5, Comm: "aider"},
		}, map[string]int{"proc.agent_name": 45}, "+2 more", "aider"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tr.Procs = tc.procs
			got := (Procs{}).Evaluate(tr, testPack(), at(1))
			g := ids(got)
			if len(g) != len(tc.want) {
				t.Fatalf("got %v want %v", g, tc.want)
			}
			for k, w := range tc.want {
				if g[k] != w {
					t.Fatalf("clue %s = %d want %d", k, g[k], w)
				}
			}
			var all []string
			for _, c := range got {
				all = append(all, c.Evidence)
			}
			if s := strings.Join(all, " | "); tc.ev != "" && !strings.Contains(s, tc.ev) {
				t.Fatalf("evidence %q lacks %q", s, tc.ev)
			}
			if a := IdentifyAgent(tr, testPack()); a != tc.agent {
				t.Fatalf("IdentifyAgent = %q want %q", a, tc.agent)
			}
		})
	}
}

func TestProcsCategories(t *testing.T) {
	tr := mkTrack("a", "1.1.1.1")
	tr.Procs = []session.ProcSample{{PID: 1, Comm: "claude", Flags: []string{"--yolo"}, Env: map[string]string{"CLAUDECODE": "1"}}}
	for _, c := range (Procs{}).Evaluate(tr, testPack(), at(1)) {
		switch c.ID {
		case "proc.agent_name", "proc.agent_env":
			if c.Category != CatProcess {
				t.Errorf("%s category %s", c.ID, c.Category)
			}
		case "proc.skip_flags":
			if c.Category != CatFlags {
				t.Errorf("%s category %s", c.ID, c.Category)
			}
		}
	}
}

func TestIdentifyAgentDeclared(t *testing.T) {
	tr := mkTrack("a", "1.1.1.1")
	tr.DeclaredAgent = "claude@2.0.1"
	if a := IdentifyAgent(tr, testPack()); a != "claude-code" {
		t.Fatalf("alias mapping: %q", a)
	}
	tr.DeclaredAgent = "my-bot"
	if a := IdentifyAgent(tr, testPack()); a != "my-bot" {
		t.Fatalf("unknown declared name should pass through: %q", a)
	}
	if a := IdentifyAgent(nil, nil); a != "" {
		t.Fatal("nil track")
	}
}
