//go:build linux

package procfs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

// Run implements readers.Reader on Linux: an immediate process scan, then
// process and connection scans on their tickers, until ctx is done. Every
// send selects on ctx so a stalled consumer can never wedge shutdown.
func (r *Reader) Run(ctx context.Context, out chan<- event.Event) error {
	root := r.opts.ProcRoot
	if _, err := os.Stat(filepath.Join(root, "self")); err != nil {
		return fmt.Errorf("procfs: %s not mounted: %w", root, err)
	}

	// The host list (and its DNS refresh) exists only for the connection
	// scan; with NetEnabled off nothing here ever resolves a name.
	resolver := r.opts.Resolver
	var hl *HostList
	if resolver == nil && r.NetEnabled {
		hl = NewHostList(r.pack)
		hl.TTL = r.opts.ResolveTTL
		resolver = hl
	}

	sc := &Scanner{
		FS:          os.DirFS(root),
		Readlink:    func(name string) (string, error) { return os.Readlink(filepath.Join(root, name)) },
		Pack:        r.pack,
		Resolver:    resolver,
		ReadEnviron: !r.opts.NoEnviron,
		MinUID:      r.opts.MinUID,
		UserLookup: NewPasswdLookup(func() (fs.File, error) {
			return os.Open(r.opts.PasswdPath)
		}),
	}

	if hl != nil {
		// DNS runs off the scan path: a slow resolver must not delay events.
		go func() {
			hl.Refresh(ctx)
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					hl.Refresh(ctx)
				}
			}
		}()
	}

	send := func(evs []event.Event) bool {
		for _, ev := range evs {
			select {
			case out <- ev:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}

	prevProc := map[int]Seen{}
	prevNet := map[uint64]bool{}

	var evs []event.Event
	evs, prevProc = sc.Scan(prevProc)
	if !send(evs) {
		return ctx.Err()
	}

	procTick := time.NewTicker(r.Interval)
	defer procTick.Stop()
	var netTick <-chan time.Time // nil channel: the case never fires
	if r.NetEnabled {
		nt := time.NewTicker(r.NetInterval)
		defer nt.Stop()
		netTick = nt.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-procTick.C:
			evs, prevProc = sc.Scan(prevProc)
			if !send(evs) {
				return ctx.Err()
			}
		case <-netTick:
			evs, prevNet = sc.ScanNet(prevNet)
			if !send(evs) {
				return ctx.Err()
			}
		}
	}
}
