package clues

import (
	"strconv"
	"strings"
	"testing"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

func TestBannerDetector(t *testing.T) {
	cases := []struct {
		name    string
		banners []string
		pack    *rules.Pack
		want    map[string]int
		ev      string
	}{
		{"none", nil, testPack(), map[string]int{}, ""},
		{"paramiko", []string{"SSH-2.0-paramiko_3.4.0"}, testPack(), map[string]int{"banner.library": 35}, "paramiko_3.4.0 (paramiko)"},
		{"asyncssh", []string{"SSH-2.0-AsyncSSH_2.14.2"}, testPack(), map[string]int{"banner.library": 35}, "asyncssh"},
		{"ssh2js", []string{"SSH-2.0-ssh2js1.17.0"}, testPack(), map[string]int{"banner.library": 35}, "ssh2js"},
		{"go", []string{"SSH-2.0-Go"}, testPack(), map[string]int{"banner.library": 35}, "(go)"},
		{"go-prefix-not-golang-ish", []string{"SSH-2.0-Gopher_1"}, testPack(), map[string]int{}, ""},
		{"russh", []string{"SSH-2.0-russh_0.44"}, testPack(), map[string]int{"banner.library": 35}, "russh"},
		{"libssh2", []string{"SSH-2.0-libssh2_1.11.0"}, testPack(), map[string]int{"banner.library": 35}, "libssh"},
		{"terraform", []string{"SSH-2.0-terraform-ssh"}, testPack(), map[string]int{"banner.automation": 15}, "terraform"},
		{"openssh", []string{"SSH-2.0-OpenSSH_9.9p1 Ubuntu-3"}, testPack(), map[string]int{"banner.human": -10}, "openssh"},
		{"putty", []string{"SSH-2.0-PuTTY_Release_0.81"}, testPack(), map[string]int{"banner.human": -10}, "putty"},
		{"mixed-two-clues", []string{"SSH-2.0-OpenSSH_9.9", "SSH-2.0-paramiko_3.4.0"}, testPack(), map[string]int{"banner.library": 35, "banner.human": -10}, ""},
		{"builtin-fallback", []string{"SSH-2.0-paramiko_3.4.0"}, &rules.Pack{}, map[string]int{"banner.library": 35}, "paramiko"},
		{"nil-pack-fallback", []string{"SSH-2.0-WinSCP_release_6.3"}, nil, map[string]int{"banner.human": -10}, "winscp"},
		{"unknown-banner", []string{"SSH-2.0-mystery_1.0"}, testPack(), map[string]int{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := mkTrack("alice", "10.0.0.5")
			tr.Connections = nil
			for i, b := range tc.banners {
				tr.Connections = append(tr.Connections, &session.Connection{ID: "cn_" + strconv.Itoa(i), User: "alice", Banner: b, Opened: at(0)})
			}
			got := (Banner{}).Evaluate(tr, tc.pack, at(10))
			if g := ids(got); len(g) != len(tc.want) {
				t.Fatalf("got %v want %v", g, tc.want)
			} else {
				for k, w := range tc.want {
					if g[k] != w {
						t.Fatalf("clue %s weight %d want %d (%v)", k, g[k], w, got)
					}
				}
			}
			if tc.ev != "" {
				all := ""
				for _, c := range got {
					all += c.Evidence + " "
				}
				if !strings.Contains(all, tc.ev) {
					t.Fatalf("evidence %q lacks %q", all, tc.ev)
				}
			}
		})
	}
}

func TestBannerInvalidRegexIsSkipped(t *testing.T) {
	p := &rules.Pack{Banners: []rules.Banner{{ID: "bad", Regex: `paramiko_(`, Kind: "library"}, {ID: "ok", Regex: `paramiko_`, Kind: "library"}}}
	tr := mkTrack("a", "1.1.1.1")
	tr.Connections[0].Banner = "SSH-2.0-paramiko_3.4.0"
	got := (Banner{}).Evaluate(tr, p, at(1))
	if len(got) != 1 || !strings.Contains(got[0].Evidence, "(ok)") {
		t.Fatalf("got %+v", got)
	}
}
