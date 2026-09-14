package clean

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTextStripsEscapesAndControls(t *testing.T) {
	in := "ba\x1b[31msh\x1b[0m\r\n\x07x\x1b]0;title\x07y\x1bZ"
	got := Text(in, MaxComm)
	if got != "bash???xy" {
		t.Fatalf("got %q", got)
	}
	if strings.ContainsAny(got, "\x1b\r\n\x07") {
		t.Fatalf("control bytes survived: %q", got)
	}
}

func TestTextCapsOnRuneBoundary(t *testing.T) {
	in := strings.Repeat("é", 100) // 2 bytes each
	got := Text(in, 65)
	if len(got) != 64 || !utf8.ValidString(got) {
		t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if Text("", 10) != "" || Truncate("abc", 0) != "abc" {
		t.Fatal("empty / uncapped handling")
	}
	if got := Text("a\xffb", 10); got != "a?b" {
		t.Fatalf("invalid utf8: %q", got)
	}
}

func TestAIAgent(t *testing.T) {
	for _, ok := range []string{"claude-code", "claude-code@2.0.1", "cursor_cli:1", "a.b+c"} {
		if got, valid := AIAgent(ok); !valid || got != ok {
			t.Errorf("%q rejected: %q %v", ok, got, valid)
		}
	}
	for _, bad := range []string{"claude code", "x;rm -rf /", "é", "\x1b[31mred", strings.Repeat("a", 65), "a\nb", "*bold*"} {
		if got, valid := AIAgent(bad); valid || got != InvalidDeclaration {
			t.Errorf("%q accepted: %q %v", bad, got, valid)
		}
	}
	if got, valid := AIAgent(""); valid || got != "" {
		t.Errorf("empty: %q %v", got, valid)
	}
	if got, valid := AIAgent(strings.Repeat("a", 100<<10)); valid || got != InvalidDeclaration {
		t.Errorf("100 KiB: len=%d %v", len(got), valid)
	}
}
