//go:build !linux

package procfs

import (
	"context"

	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/readers"
)

// Run implements readers.Reader; /proc exists only on Linux.
func (r *Reader) Run(ctx context.Context, out chan<- event.Event) error {
	return readers.ErrUnsupportedPlatform
}
