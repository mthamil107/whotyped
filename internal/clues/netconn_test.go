package clues

import (
	"strings"
	"testing"

	"github.com/whotyped/whotyped/internal/session"
)

func TestNetConnDetector(t *testing.T) {
	cases := []struct {
		name  string
		conns []session.NetSample
		want  map[string]int
		ev    string
		agent string
	}{
		{"none", nil, map[string]int{}, "", ""},
		{"github-not-ai", []session.NetSample{{Dst: "140.82.112.3", DstPort: 443, Host: "github.com", PID: 1, Attributed: true}}, map[string]int{}, "", ""},
		{"anthropic-attributed", []session.NetSample{{Dst: "160.79.104.10", DstPort: 443, Host: "api.anthropic.com", PID: 4411, Attributed: true}},
			map[string]int{"net.ai_api": 30}, "api.anthropic.com:443 from pid 4411", "claude-code"},
		{"anthropic-by-cidr-no-host", []session.NetSample{{Dst: "160.79.105.7", DstPort: 443, Attributed: true}},
			map[string]int{"net.ai_api": 30}, "160.79.105.7:443", "claude-code"},
		{"openai-unattributed", []session.NetSample{{Dst: "104.18.6.192", DstPort: 443, Host: "api.openai.com"}},
			map[string]int{"net.ai_api_unattributed": 15}, "api.openai.com:443 (uid only)", "codex"},
		{"subdomain-suffix", []session.NetSample{{Dst: "1.1.1.1", DstPort: 443, Host: "eu.api.openai.com", Attributed: true}},
			map[string]int{"net.ai_api": 30}, "", "codex"},
		{"not-a-suffix-lookalike", []session.NetSample{{Dst: "1.1.1.1", DstPort: 443, Host: "notapi.openai.com.evil.example", Attributed: true}},
			map[string]int{}, "", ""},
		{"wrong-port", []session.NetSample{{Dst: "1.1.1.1", DstPort: 8080, Host: "api.anthropic.com", Attributed: true}},
			map[string]int{}, "", ""},
		{"ollama-explicit-port", []session.NetSample{{Dst: "127.0.0.1", DstPort: 11434, Attributed: true, PID: 8}},
			map[string]int{"net.ai_api": 30}, "127.0.0.1:11434 from pid 8", ""},
		{"reader-prematched-agent", []session.NetSample{{Dst: "9.9.9.9", DstPort: 443, Host: "api.mistral.ai", Agent: "mistral", Attributed: true}},
			map[string]int{"net.ai_api": 30}, "", "mistral"},
		{"both-kinds", []session.NetSample{
			{Dst: "1.1.1.1", DstPort: 443, Host: "openrouter.ai", Attributed: true, PID: 5},
			{Dst: "1.1.1.2", DstPort: 443, Host: "generativelanguage.googleapis.com"},
		}, map[string]int{"net.ai_api": 30, "net.ai_api_unattributed": 15}, "", "gemini-cli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tr.NetConns = tc.conns
			got := (NetConn{}).Evaluate(tr, testPack(), at(1))
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
				if c.Category != CatNetwork {
					t.Errorf("category %s", c.Category)
				}
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

func TestNetConnNilPackOnlyReaderMatches(t *testing.T) {
	tr := mkTrack("a", "1.1.1.1")
	tr.NetConns = []session.NetSample{
		{Dst: "1.1.1.1", DstPort: 443, Host: "api.anthropic.com", Attributed: true},
		{Dst: "1.1.1.2", DstPort: 443, Host: "api.openai.com", Agent: "codex", Attributed: true},
	}
	got := (NetConn{}).Evaluate(tr, nil, at(1))
	if len(got) != 1 || !strings.Contains(got[0].Evidence, "api.openai.com") {
		t.Fatalf("got %+v", got)
	}
}
