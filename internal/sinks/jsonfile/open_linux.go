//go:build linux

package jsonfile

import (
	"os"
	"syscall"
)

// openAppend opens (creating if needed) the alerts file for append without
// following a symlink at the final path component.
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o640)
}
