package clues

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cmd := "bash -c cd /srv/app && cat /etc/secret.conf | head -n 20"
	cases := []struct {
		mode, want string
	}{
		{"redacted", "bash … (len 56)"},
		{"", "bash … (len 56)"},
		{"full", cmd},
		{"none", ""},
	}
	for _, tc := range cases {
		if got := Redact(cmd, tc.mode); got != tc.want {
			t.Errorf("Redact(%q) = %q want %q", tc.mode, got, tc.want)
		}
	}
	if got := Redact("", "redacted"); got != "" {
		t.Errorf("empty: %q", got)
	}
	if got := Redact("line1\nfake sshd[1]: Accepted publickey", "full"); strings.Contains(got, "\n") {
		t.Errorf("newline survived: %q", got)
	}
}

func TestFragment(t *testing.T) {
	if got := Fragment("cat <<'EOF' > x", "cat <<'EOF'"); got != "cat <<'EOF'" {
		t.Errorf("got %q", got)
	}
	if got := Fragment("git   status", ""); got != "git" {
		t.Errorf("argv0 fallback: %q", got)
	}
	long := strings.Repeat("é", 100)
	got := Fragment(long, long)
	if len(got) > maxFragment+len("…") || !strings.HasSuffix(got, "…") {
		t.Errorf("truncation: %d bytes %q", len(got), got)
	}
	if got := Fragment("", "a\tb\x00c\r\nd"); got != "a bc d" {
		t.Errorf("control chars: %q", got)
	}
}

func TestIdentityDetector(t *testing.T) {
	tr := mkTrack("alice", "10.0.0.5")
	if got := (Identity{}).Evaluate(tr, testPack(), at(1)); len(got) != 0 {
		t.Fatalf("undeclared: %v", got)
	}
	tr.DeclaredAgent = "claude-code@2.0.1"
	got := (Identity{}).Evaluate(tr, testPack(), at(1))
	if len(got) != 1 || got[0].ID != "env.ai_agent" || got[0].Category != CatIdentity || got[0].Weight != 0 || got[0].Evidence != "AI_AGENT=claude-code@2.0.1" {
		t.Fatalf("got %+v", got)
	}
}

func TestAllDetectorsHaveUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range All() {
		if seen[d.ID()] {
			t.Fatalf("duplicate detector id %s", d.ID())
		}
		seen[d.ID()] = true
		if got := d.Evaluate(nil, nil, at(0)); len(got) != 0 {
			t.Fatalf("%s: nil track produced clues", d.ID())
		}
	}
	if len(seen) != 7 {
		t.Fatalf("expected 7 detectors, got %d", len(seen))
	}
}
