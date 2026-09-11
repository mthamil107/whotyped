package score

import (
	"testing"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

func TestMatchProfileAnyOfRatio(t *testing.T) {
	p := testPack()
	cases := []struct {
		name  string
		build func(*session.Track)
		want  string
		ratio float64
	}{
		{"no-execs-no-banner", func(*session.Track) {}, "", 0},
		{"ansible-by-commands", func(tr *session.Track) {
			addCmds(tr, 0, 2,
				"/bin/sh -c 'echo ~ansible && sleep 0'",
				"/bin/sh -c '/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py && sleep 0'",
				"/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py",
				"/bin/sh -c 'rm -f -r /home/ansible/.ansible/tmp/ansible-tmp-1/ > /dev/null 2>&1 && sleep 0'",
				"uname -a") // one stray command: 4/5 = 0.8 still passes
		}, "ansible", 0.8},
		{"ansible-ratio-too-low", func(tr *session.Track) {
			addCmds(tr, 0, 2, "/bin/sh -c 'echo ~ansible && sleep 0'", "ls", "pwd", "id", "whoami")
		}, "", 0},
		{"ansible-by-banner-only", func(tr *session.Track) {
			tr.Connections[0].Banner = "SSH-2.0-paramiko_2.12.0"
			addExecChannels(tr, 10, 0, 1) // sshlog channels carry no text and do not vote
		}, "ansible", 1},
		{"vscode-lower-ratio", func(tr *session.Track) {
			addCmds(tr, 0, 5,
				"bash -c ~/.vscode-server/bin/abc/bin/code-server --start-server",
				"git -c core.quotepath=false -c color.ui=false status -z -uall",
				"git -c core.quotepath=false -c color.ui=false rev-parse --show-toplevel",
				"ls", "npm test", "git -c core.quotepath=false log",
				"git -c core.quotepath=false status -z", "git -c core.quotepath=false status -z",
				"git -c core.quotepath=false status -z", "git -c core.quotepath=false status -z") // 8/10
		}, "vscode-remote", 0.8},
		{"runner-needs-user-cidr-and-path", func(tr *session.Track) {
			tr.Key.User, tr.Key.SrcIP = "runner", "10.200.4.7"
			addCmds(tr, 0, 1, "/home/runner/work/_temp/abc.sh", "bash -e /home/runner/work/repo/repo/build.sh")
		}, "github-runner", 1},
		{"runner-wrong-cidr", func(tr *session.Track) {
			tr.Key.User, tr.Key.SrcIP = "runner", "10.9.0.1"
			addCmds(tr, 0, 1, "/home/runner/work/_temp/abc.sh")
		}, "", 0},
		{"runner-wrong-user", func(tr *session.Track) {
			tr.Key.User, tr.Key.SrcIP = "alice", "10.200.4.7"
			addCmds(tr, 0, 1, "/home/runner/work/_temp/abc.sh")
		}, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tc.build(tr)
			prof, ratio := MatchProfile(tr, p)
			got := ""
			if prof != nil {
				got = prof.ID
			}
			if got != tc.want {
				t.Fatalf("profile %q (ratio %.2f) want %q", got, ratio, tc.want)
			}
			if tc.want != "" && ratio+1e-9 < tc.ratio {
				t.Fatalf("ratio %.2f < %.2f", ratio, tc.ratio)
			}
		})
	}
}

func TestMatchProfileStaticConditions(t *testing.T) {
	tr := mkTrack("deploy", "192.168.1.10")
	p := &rules.Pack{Profiles: []rules.Profile{
		{ID: "empty-never-matches", Match: rules.Match{}, Suppress: []string{"rhythm"}},
		{ID: "disabled", Match: rules.Match{Users: []string{"deploy"}}, Disabled: true},
		{ID: "glob-user", Match: rules.Match{Users: []string{"dep*"}, Fingerprints: []string{"SHA256:abc"}, SrcCIDRs: []string{"192.168.1.10"}}},
	}}
	prof, ratio := MatchProfile(tr, p)
	if prof == nil || prof.ID != "glob-user" || ratio != 1 {
		t.Fatalf("got %v %.2f", prof, ratio)
	}
	if prof, _ := MatchProfile(tr, nil); prof != nil {
		t.Fatal("nil pack matched")
	}
	tr.Key.SrcIP = "local"
	if prof, _ := MatchProfile(tr, p); prof != nil {
		t.Fatal("non-IP source must not match a CIDR")
	}
}

func TestApplyProfileSuppression(t *testing.T) {
	in := []clues.Clue{
		{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20},
		{ID: "pty.none", Category: clues.CatPTY, Weight: 15},
		{ID: "pty.interactive", Category: clues.CatPTY, Weight: -15},
		{ID: "proc.agent_name", Category: clues.CatProcess, Weight: 45},
		{ID: "proc.skip_flags", Category: clues.CatFlags, Weight: 25},
		{ID: "env.ai_agent", Category: clues.CatIdentity, Weight: 0},
		{ID: "style.heredoc", Category: clues.CatStyle, Weight: 10},
	}
	prof := &rules.Profile{ID: "p", Suppress: []string{"rhythm", "pty.none", "process", "flags", "identity"}}
	kept, sup := applyProfile(prof, in)
	if len(sup) != 2 || len(kept) != 5 {
		t.Fatalf("kept %v sup %v", kept, sup)
	}
	for _, s := range sup {
		if s.Profile != "p" || (s.Clue != "rhythm.burst" && s.Clue != "pty.none") {
			t.Fatalf("suppression %+v", s)
		}
	}
	prof.AllowAgentProcesses = true
	kept, sup = applyProfile(prof, in)
	if len(sup) != 5 || len(kept) != 2 {
		t.Fatalf("allow_agent_processes: kept %v sup %v", kept, sup)
	}
}

func TestProfileInScorerMaxScoreAndProtection(t *testing.T) {
	// Ansible-shaped track: banner + rhythm + pty + style would be ~100 raw.
	tr := mkTrack("ansible", "10.0.0.20")
	tr.Connections[0].Banner = "SSH-2.0-paramiko_2.12.0"
	addExecChannels(tr, 12, 0, 1.5)
	var cmds []string
	for i := 0; i < 12; i++ {
		cmds = append(cmds, "/bin/sh -c '/usr/bin/python3 /home/ansible/.ansible/tmp/ansible-tmp-1/AnsiballZ_setup.py && sleep 0'")
	}
	addCmds(tr, 0.05, 1.5, cmds...)
	v := newTestScorer().Evaluate(tr, testPack(), at(100))
	if v.Profile != "ansible" || v.Score != 0 || v.Class != ClassHuman || len(v.Suppressed) < 4 {
		t.Fatalf("ansible profile: %+v", v)
	}
	// An agent process on the same track is never hidden by the profile.
	tr.Procs = []session.ProcSample{{PID: 1, Comm: "claude", Flags: []string{"--dangerously-skip-permissions"}}}
	v = newTestScorer().Evaluate(tr, testPack(), at(100))
	if v.Score != 70 || v.Level != LevelAlert || v.Class != ClassSuspected || v.Agent != "?claude-code" {
		t.Fatalf("protected categories: %+v", v)
	}
	// max_score applies when only suppressible categories remain above it.
	tr.Procs = nil
	p := testPack()
	p.Profiles[0].Suppress = []string{"banner"} // leave rhythm/pty/style alone: raw ~65
	v = newTestScorer().Evaluate(tr, p, at(100))
	if v.Score != 20 || v.Profile != "ansible" {
		t.Fatalf("max_score: %+v", v)
	}
}

// TestRequiredClauseAndPrefixSuppress covers the two allowlist semantics the
// shipped vscode-remote profile relies on: a `required: true` clause that at
// least one command must satisfy on top of the ratio (so git polling alone
// never allowlists a session), and suppress entries that match by id prefix
// ("style.pager_guard" covers "style.pager_guard.head").
func TestRequiredClauseAndPrefixSuppress(t *testing.T) {
	prof := rules.Profile{ID: "vscode", Match: rules.Match{MinMatchRatio: 0.5, AnyOf: []rules.MatchClause{
		{Required: true, PathRegex: `/\.vscode-server/`},
		{CmdRegex: `^git\s+(?:-c\s+\S+\s+)*(?:status|rev-parse)\b`},
	}}, Suppress: []string{"rhythm", "style.pager_guard", "style.tool_wrapper"}, MaxScore: 30}
	pack := &rules.Pack{Profiles: []rules.Profile{prof}}

	gitOnly := mkTrack("alice", "10.0.0.5")
	addCmds(gitOnly, 0, 5, "git -c core.quotepath=false status -z", "git rev-parse --show-toplevel", "git status")
	if p, _ := MatchProfile(gitOnly, pack); p != nil {
		t.Fatalf("git-only track matched %s; the required clause must anchor the profile", p.ID)
	}

	withServer := mkTrack("alice", "10.0.0.5")
	addCmds(withServer, 0, 5,
		"/home/alice/.vscode-server/bin/abc/node /home/alice/.vscode-server/bin/abc/out/server-main.js --start-server",
		"git -c core.quotepath=false status -z", "git rev-parse --show-toplevel", "npm test")
	p, ratio := MatchProfile(withServer, pack)
	if p == nil || ratio < 0.74 || ratio > 0.76 {
		t.Fatalf("expected match at ratio 0.75, got %v %v", p, ratio)
	}

	noisy := mkTrack("alice", "10.0.0.5")
	addCmds(noisy, 0, 5, "/home/alice/.vscode-server/bin/abc/node x.js", "npm test", "make", "ls", "cat a")
	if p, _ := MatchProfile(noisy, pack); p != nil {
		t.Fatalf("required clause satisfied but ratio 0.2 still matched %s", p.ID)
	}

	in := []clues.Clue{
		{ID: "style.pager_guard.head", Category: clues.CatStyle, Weight: 5},
		{ID: "style.pager_guard.stderr_merge", Category: clues.CatStyle, Weight: 5},
		{ID: "style.tool_wrapper", Category: clues.CatStyle, Weight: 8},
		{ID: "style.tool_wrapperish", Category: clues.CatStyle, Weight: 8},
		{ID: "style.heredoc", Category: clues.CatStyle, Weight: 10},
		{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20},
	}
	kept, sup := applyProfile(&prof, in)
	if len(sup) != 4 || len(kept) != 2 {
		t.Fatalf("prefix suppression: kept %v sup %v", kept, sup)
	}
	for _, c := range kept {
		if c.ID != "style.heredoc" && c.ID != "style.tool_wrapperish" {
			t.Errorf("unexpectedly suppressed by prefix: %s", c.ID)
		}
	}
}
