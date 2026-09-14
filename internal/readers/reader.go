// Package readers defines the Reader interface every log/proc source implements.
package readers

import (
	"context"
	"errors"

	"github.com/mthamil107/whotyped/internal/event"
)

// ErrUnsupportedPlatform is returned by Linux-only readers on other OSes.
var ErrUnsupportedPlatform = errors.New("reader not supported on this platform")

// Reader pushes events until ctx is done. Run must return promptly on cancel
// and must never block forever on a full channel (use select with ctx).
type Reader interface {
	Name() string
	Run(ctx context.Context, out chan<- event.Event) error
}
