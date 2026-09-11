package simulate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
)

// TestOfflineScenariosPass replays every embedded scenario with the shipped
// rule pack; each must match its own expected.json.
func TestOfflineScenariosPass(t *testing.T) {
	for _, name := range List() {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			code := RunOffline(name, &out, false)
			if code != ExitMatch {
				t.Fatalf("exit %d\n%s", code, out.String())
			}
			if !strings.Contains(out.String(), "PASS") {
				t.Fatalf("no PASS line:\n%s", out.String())
			}
		})
	}
}

func TestOfflineKnownScores(t *testing.T) {
	cases := map[string]int{"claude-bash": 75, "paramiko-mcp": 88, "local-agent": 100, "human": 0, "vscode": 0, "ansible": 0}
	for alias, want := range cases {
		res, err := Evaluate(alias)
		if err != nil {
			t.Fatal(err)
		}
		if res.Verdict.Score != want {
			t.Errorf("%s: score %d, want %d", alias, res.Verdict.Score, want)
		}
	}
}

func TestOfflineJSONAndList(t *testing.T) {
	var out bytes.Buffer
	if code := RunOffline("claude-bash", &out, true); code != ExitMatch {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("json: %v", err)
	}
	if res.Scenario != "claude-bash-over-ssh" || !res.Pass {
		t.Fatalf("unexpected result %+v", res)
	}
	out.Reset()
	if code := RunOffline("list", &out, false); code != ExitMatch || !strings.Contains(out.String(), "mcp-paramiko") {
		t.Fatalf("list: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := RunOffline("no-such-scenario", &out, false); code != ExitTimeout {
		t.Fatalf("unknown scenario exit %d", code)
	}
}

func TestExplainMissing(t *testing.T) {
	var out bytes.Buffer
	explainMissing(&out, alert.Alert{Reasons: []clues.Clue{{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20}}})
	s := out.String()
	if !strings.Contains(s, "auditd") || strings.Contains(s, "LogLevel is not VERBOSE") == false {
		// rhythm present but pty absent still points at VERBOSE; style/flags absent points at auditd.
		t.Fatalf("unexpected explanation:\n%s", s)
	}
}

func TestSSHArgs(t *testing.T) {
	args := sshArgs(Options{Declared: true}, "alice@host", false, "echo 'hi'")
	joined := strings.Join(args, " ")
	for _, want := range []string{"BatchMode=yes", "ControlMaster=no", "SetEnv=AI_AGENT=whotyped-simulate", "-T", "alice@host -- bash -lc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if args[len(args)-1] != `'echo '\''hi'\'''` {
		t.Errorf("bad quoting: %s", args[len(args)-1])
	}
	if targetUser("bob@example") != "bob" {
		t.Error("targetUser")
	}
}
