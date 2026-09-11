package clues

import (
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

// Banner weights by kind. A library banner is strong (nobody types through
// paramiko) but shared with Ansible/Terraform, so it cannot alert alone.
const (
	WeightBannerLibrary    = 35
	WeightBannerAutomation = 15
	WeightBannerHuman      = -10
)

// Banner classifies the SSH client software version strings seen on a track.
// The banner is only logged at sshd LogLevel DEBUG1, so this detector is
// often silent.
type Banner struct{}

// ID implements Detector.
func (Banner) ID() string { return "banner" }

// builtinBanners is used when the pack carries no banner rules (tests, replay
// without rules). It mirrors rules/banners.yaml.
var builtinBanners = []rules.Banner{
	{ID: "paramiko", Regex: `paramiko_`, Kind: "library"},
	{ID: "asyncssh", Regex: `AsyncSSH_`, Kind: "library"},
	{ID: "ssh2js", Regex: `ssh2js`, Kind: "library"},
	{ID: "go", Regex: `^SSH-2\.0-Go(\s|$)`, Kind: "library"},
	{ID: "russh", Regex: `russh_`, Kind: "library"},
	{ID: "libssh", Regex: `libssh2?_`, Kind: "library"},
	{ID: "jsch", Regex: `JSCH`, Kind: "library"},
	{ID: "sshj", Regex: `SSHJ_`, Kind: "library"},
	{ID: "terraform", Regex: `terraform`, Kind: "automation"},
	{ID: "fabric", Regex: `fabric`, Kind: "automation"},
	{ID: "openssh", Regex: `OpenSSH_`, Kind: "human"},
	{ID: "putty", Regex: `PuTTY`, Kind: "human"},
	{ID: "winscp", Regex: `WinSCP`, Kind: "human"},
	{ID: "mobaxterm", Regex: `MobaXterm`, Kind: "human"},
}

// Evaluate implements Detector. One clue per kind at most; the evidence lists
// the banners and the rule ids that matched.
func (Banner) Evaluate(t *session.Track, p *rules.Pack, now time.Time) []Clue {
	if t == nil {
		return nil
	}
	banners := t.Banners()
	if len(banners) == 0 {
		return nil
	}
	rs := builtinBanners
	if p != nil && len(p.Banners) > 0 {
		rs = p.Banners
	}
	kinds := map[string][]string{} // kind -> evidence parts
	for _, b := range banners {
		for _, r := range rs {
			if r.Disabled {
				continue
			}
			re := compile(r.Regex)
			if re == nil || !re.MatchString(b) {
				continue
			}
			kinds[r.Kind] = append(kinds[r.Kind], Fragment("", b)+" ("+r.ID+")")
			break // first matching rule per banner
		}
	}
	var out []Clue
	add := func(kind, id string, w int) {
		if parts := kinds[kind]; len(parts) > 0 {
			out = append(out, Clue{ID: id, Category: CatBanner, Weight: w, Evidence: strings.Join(parts, ", "), TS: now})
		}
	}
	add("library", "banner.library", WeightBannerLibrary)
	add("automation", "banner.automation", WeightBannerAutomation)
	add("human", "banner.human", WeightBannerHuman)
	return out
}
