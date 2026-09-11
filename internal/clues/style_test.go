package clues

import (
	"strings"
	"testing"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

func TestStyleBuiltins(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want map[string]int
		ev   string // substring expected in some evidence
		not  string // substring that must never appear (privacy)
	}{
		{"empty", nil, map[string]int{}, "", ""},
		{"plain-human", []string{"ls -la", "cd /srv", "vim app.py", "git status"}, map[string]int{}, "", ""},
		{"heredoc-3x", []string{
			"cat <<'EOF' > /tmp/a.txt\nsecret line\nEOF", "cat <<EOF >> /etc/x\nfoo\nEOF", "bash -c cat <<-'PY' | python3\nprint(1)\nPY",
		}, map[string]int{"style.heredoc": 10, "style.tool_wrapper": 8}, "cat <<'EOF' (3x)", "secret line"},
		{"compound-cd-and", []string{"cd /srv/app && git pull"}, map[string]int{"style.compound": 10}, "cd /srv/app && (1x)", ""},
		{"compound-long-ops", []string{
			"grep -r TODO src | sort | uniq -c | sort -rn ; echo done and this line is intentionally longer than eighty characters",
		}, map[string]int{"style.compound": 10}, "operators, len", "TODO"},
		{"compound-short-ops-not", []string{"ls | wc -l ; echo"}, map[string]int{}, "", ""},
		{"tool-wrapper-forms", []string{"bash -lc echo hi", "/bin/sh -c ls", "/usr/bin/bash -c pwd", "zsh -c true"},
			map[string]int{"style.tool_wrapper": 8}, "bash -lc (4x)", ""},
		{"pager-guards-each-once-per-cmd", []string{
			"journalctl -u nginx --no-pager | tail -n 50 2>&1",
			"git log --no-pager --oneline | head -n 20",
			"sed -n '10,40p' /etc/nginx/nginx.conf",
			"timeout 30 systemctl status app 2>&1 | head -20",
		}, map[string]int{
			"style.pager_guard.nopager": 5, "style.pager_guard.head": 5, "style.pager_guard.tail": 5,
			"style.pager_guard.sed_range": 5, "style.pager_guard.stderr_merge": 5, "style.pager_guard.timeout": 5,
		}, "--no-pager (2x)", "nginx.conf"},
		{"abs-paths-needs-three-cmds", []string{
			"cp /etc/a /etc/b /var/tmp/c", "diff /srv/x /srv/y /srv/z",
		}, map[string]int{}, "", ""},
		{"abs-paths", []string{
			"cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak /var/backups/", "ls /srv/app /var/log/app /etc/app.d",
			"cat /proc/cpuinfo /proc/meminfo /etc/os-release",
		}, map[string]int{"style.abs_paths": 5}, "/etc/nginx/nginx.conf +2 paths (3x)", ""},
		{"abs-paths-duplicates-not-distinct", []string{"ls /a /a /a", "ls /b /b /b", "ls /c /c /c"}, map[string]int{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			addCmds(tr, tc.cmds...)
			got := (Style{}).Evaluate(tr, &rules.Pack{}, at(500))
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
			s := strings.Join(all, " | ")
			if tc.ev != "" && !strings.Contains(s, tc.ev) {
				t.Fatalf("evidence %q lacks %q", s, tc.ev)
			}
			if tc.not != "" && strings.Contains(s, tc.not) {
				t.Fatalf("evidence %q leaks %q", s, tc.not)
			}
		})
	}
}

func TestStyleUsesPackRulesAndGroupNaming(t *testing.T) {
	tr := mkTrack("alice", "10.0.0.5")
	addCmds(tr, "bash -c cd /srv && git log --no-pager | head -n 5 2>&1", "cat <<'EOF'\nx\nEOF")
	got := (Style{}).Evaluate(tr, testPack(), at(500))
	g := ids(got)
	for _, id := range []string{"style.heredoc", "style.tool_wrapper", "style.pager_guard.no_pager", "style.pager_guard.head", "style.pager_guard.stderr"} {
		if _, ok := g[id]; !ok {
			t.Errorf("missing %s in %v", id, g)
		}
	}
	// The pack's compound regex requires a leading `cd`, so the wrapped command does not match.
	if _, ok := g["style.compound"]; ok {
		t.Errorf("pack compound regex should not match a bash -c prefix: %v", g)
	}
	if g["style.pager_guard.no_pager"] != 5 {
		t.Errorf("pack weight not used: %v", g)
	}
}

func TestStyleEvidenceNeverFullCommand(t *testing.T) {
	long := "bash -c " + strings.Repeat("A", 300) + " --no-pager"
	tr := mkTrack("a", "1.1.1.1")
	addCmds(tr, long)
	for _, c := range (Style{}).Evaluate(tr, nil, at(1)) {
		if len(c.Evidence) > maxFragment+16 {
			t.Fatalf("evidence too long (%d): %q", len(c.Evidence), c.Evidence)
		}
	}
}

func TestStyleSkipsSamplesWithoutText(t *testing.T) {
	tr := mkTrack("a", "1.1.1.1")
	addExecChannels(tr, 10, 0, 1) // sshlog channels carry no command text
	if got := (Style{}).Evaluate(tr, testPack(), at(1)); len(got) != 0 {
		t.Fatalf("unexpected clues %v", got)
	}
	_ = session.ExecSample{}
}

// TestStyleIDsAgainstEmbeddedPack pins the exact clue ids the detector emits
// with the shipped rules/styles.yaml. Pack ids already carry the "style."
// prefix; a regression here would surface as "style.style.compound" in
// alerts and break allowlist suppress entries and the pager_guard cap.
func TestStyleIDsAgainstEmbeddedPack(t *testing.T) {
	pack, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	tr := mkTrack("alice", "10.0.0.5")
	addCmds(tr,
		"bash -lc 'cd /srv/app && git --no-pager log -3 2>&1 | head -n 20'",
		"cat <<'EOF' > /tmp/x\nhello\nEOF",
		"timeout 30 sh -c 'sed -n \"10,20p\" /etc/hosts | tail -n 5'",
		"ls -la /home/deploy/app/config /home/deploy/app/logs",
		"PAGER=cat git diff /srv/app/a /srv/app/b",
	)
	got := ids((Style{}).Evaluate(tr, pack, at(500)))
	want := []string{
		"style.heredoc", "style.compound", "style.tool_wrapper", "style.abs_paths",
		"style.pager_guard.nopager", "style.pager_guard.head", "style.pager_guard.tail",
		"style.pager_guard.sed_range", "style.pager_guard.stderr_merge", "style.pager_guard.timeout",
	}
	if len(got) != len(want) {
		t.Errorf("got %d ids %v, want %d", len(got), got, len(want))
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s in %v", id, got)
		}
	}
	for id := range got {
		if strings.HasPrefix(id, "style.style.") || strings.Contains(id, ".style.") {
			t.Errorf("doubled prefix in %s", id)
		}
	}
}
