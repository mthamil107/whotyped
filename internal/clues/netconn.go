package clues

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/mthamil107/whotyped/internal/rules"
	"github.com/mthamil107/whotyped/internal/session"
)

const (
	WeightNetAIAPI             = 30
	WeightNetAIAPIUnattributed = 15
)

// NetConn matches outbound connections against the AI API host rules. A
// connection joined to the track by session or pid is worth more than one
// only known to come from the same uid.
type NetConn struct{}

// ID implements Detector.
func (NetConn) ID() string { return "netconn" }

// Evaluate implements Detector.
func (NetConn) Evaluate(t *session.Track, p *rules.Pack, now time.Time) []Clue {
	if t == nil || len(t.NetConns) == 0 {
		return nil
	}
	var attributed, weak []string
	seen := map[string]bool{} // the same process reconnects many times; say it once
	for _, n := range t.NetConns {
		h := matchHost(n, p)
		if h == nil && n.Agent == "" {
			continue
		}
		ev := netEvidence(n)
		if seen[ev] {
			continue
		}
		seen[ev] = true
		if n.Attributed {
			attributed = append(attributed, ev)
		} else {
			weak = append(weak, ev)
		}
	}
	var out []Clue
	if len(attributed) > 0 {
		out = append(out, Clue{ID: "net.ai_api", Category: CatNetwork, Weight: WeightNetAIAPI, Evidence: joinEvidence(attributed), TS: now})
	}
	if len(weak) > 0 {
		out = append(out, Clue{ID: "net.ai_api_unattributed", Category: CatNetwork, Weight: WeightNetAIAPIUnattributed, Evidence: joinEvidence(weak), TS: now})
	}
	return out
}

func netEvidence(n session.NetSample) string {
	target := n.Host
	if target == "" {
		target = n.Dst
	}
	s := fmt.Sprintf("%s:%d", Fragment("", target), n.DstPort)
	switch {
	case n.PID != 0:
		return s + fmt.Sprintf(" from pid %d", n.PID)
	case !n.Attributed:
		return s + " (uid only)"
	}
	return s
}

// matchHost returns the API host rule matching the sample by hostname suffix,
// exact address or CIDR, honouring the rule port (0 means 443).
func matchHost(n session.NetSample, p *rules.Pack) *rules.Host {
	if p == nil {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(n.Host, "."))
	addr, addrErr := netip.ParseAddr(n.Dst)
	hasAddr := addrErr == nil
	for i := range p.APIHosts {
		h := &p.APIHosts[i]
		if h.Disabled {
			continue
		}
		port := h.Port
		if port == 0 {
			port = 443
		}
		if n.DstPort != 0 && n.DstPort != port {
			continue
		}
		if rh := strings.ToLower(h.Host); rh != "" {
			if host == rh || strings.HasSuffix(host, "."+rh) || n.Dst == rh {
				return h
			}
		}
		if h.CIDR != "" && hasAddr {
			if pfx, err := netip.ParsePrefix(h.CIDR); err == nil && pfx.Contains(addr.Unmap()) {
				return h
			}
		}
	}
	return nil
}
