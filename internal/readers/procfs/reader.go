package procfs

import (
	"time"

	"github.com/whotyped/whotyped/internal/rules"
)

// Options tunes the live reader. Zero values pick the defaults below.
type Options struct {
	Interval    time.Duration // process scan period, default 5 s
	NetInterval time.Duration // connection scan period, default 10 s
	ProcRoot    string        // default /proc
	PasswdPath  string        // default /etc/passwd
	MinUID      int           // see Scanner.MinUID
	NoEnviron   bool          // skip /proc/PID/environ (loses env-only and AI_AGENT clues)
	NoNet       bool          // skip the /proc/net connection scan entirely (readers.netconn.enabled: false)
	Resolver    Resolver      // default: HostList over pack.APIHosts, refreshed every minute
	ResolveTTL  time.Duration // HostList cache TTL, default 10 min
}

// Reader is the procfs readers.Reader. The type, New and Name are portable so
// cmd/ compiles everywhere; Run lives in reader_linux.go / reader_other.go.
// NetEnabled is true by default (zero Options); Options.NoNet clears it and
// then Run never opens /proc/net/tcp*, never builds the DNS host list and
// emits no net.conn events, so the net.ai_api clue family cannot fire.
type Reader struct {
	Interval    time.Duration
	NetInterval time.Duration
	NetEnabled  bool

	pack *rules.Pack
	opts Options
}

// New builds a Reader over pack with opts.
func New(pack *rules.Pack, opts Options) *Reader {
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.NetInterval <= 0 {
		opts.NetInterval = 10 * time.Second
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.PasswdPath == "" {
		opts.PasswdPath = "/etc/passwd"
	}
	if opts.ResolveTTL <= 0 {
		opts.ResolveTTL = 10 * time.Minute
	}
	return &Reader{Interval: opts.Interval, NetInterval: opts.NetInterval, NetEnabled: !opts.NoNet, pack: pack, opts: opts}
}

// Name implements readers.Reader.
func (r *Reader) Name() string { return "procfs" }
