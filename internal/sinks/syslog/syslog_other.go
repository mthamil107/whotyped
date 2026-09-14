//go:build !linux

package syslog

import "github.com/mthamil107/whotyped/internal/alert"

// New validates its arguments and then reports that syslog is unavailable
// here, so config errors surface the same way on every platform.
func New(tag, facility string) (alert.Sink, error) {
	if _, _, err := normalise(tag, facility); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
