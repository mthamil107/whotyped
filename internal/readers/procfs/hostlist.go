package procfs

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
)

// HostList is the runtime Resolver: it resolves every hostname in the
// api_hosts rules and caches the answers for TTL. Lookup never touches the
// network, so scans stay fast; the Linux reader calls Refresh from its own
// goroutine. Literal-IP and CIDR rules are handled by HostFor directly.
type HostList struct {
	TTL      time.Duration // default 10 min
	Timeout  time.Duration // per-host lookup deadline, default 5 s
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)

	mu    sync.Mutex
	hosts []string
	cache map[string]hostEntry
}

type hostEntry struct {
	ips []string
	at  time.Time
}

// NewHostList collects the hostnames from pack.APIHosts.
func NewHostList(pack *rules.Pack) *HostList {
	h := &HostList{
		TTL:     10 * time.Minute,
		Timeout: 5 * time.Second,
		cache:   map[string]hostEntry{},
	}
	h.LookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}
	if pack == nil {
		return h
	}
	for _, r := range pack.APIHosts {
		if r.Disabled || r.Host == "" {
			continue
		}
		if _, err := netip.ParseAddr(r.Host); err == nil {
			continue // literal IP, no DNS needed
		}
		h.hosts = appendUnique(h.hosts, r.Host)
	}
	return h
}

// Hosts returns the hostnames that will be resolved.
func (h *HostList) Hosts() []string {
	return append([]string(nil), h.hosts...)
}

// Lookup implements Resolver from the cache only.
func (h *HostList) Lookup(host string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cache[host].ips
}

// Refresh re-resolves every host whose cache entry is older than TTL. A
// failed lookup keeps the previous answer so a DNS blip does not blind the
// network clue; it is retried on the next call.
func (h *HostList) Refresh(ctx context.Context) {
	now := time.Now()
	for _, host := range h.hosts {
		h.mu.Lock()
		e, ok := h.cache[host]
		h.mu.Unlock()
		if ok && now.Sub(e.at) < h.TTL {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		lctx, cancel := context.WithTimeout(ctx, h.Timeout)
		ips, err := h.LookupIP(lctx, host)
		cancel()
		if err != nil {
			continue
		}
		strs := make([]string, 0, len(ips))
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				strs = append(strs, a.Unmap().String())
			}
		}
		h.mu.Lock()
		h.cache[host] = hostEntry{ips: strs, at: now}
		h.mu.Unlock()
	}
}
