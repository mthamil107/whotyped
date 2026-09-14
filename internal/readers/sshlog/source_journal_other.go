//go:build !linux

package sshlog

import (
	"context"

	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/readers"
)

// Run is unavailable off Linux: there is no journald to follow.
func (s *JournalSource) Run(ctx context.Context, out chan<- event.Event) error {
	return readers.ErrUnsupportedPlatform
}
