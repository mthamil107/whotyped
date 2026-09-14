//go:build !linux

package jsonfile

import "os"

// openAppend opens (creating if needed) the alerts file for append. Platforms
// without O_NOFOLLOW rely on the Lstat check in Sink.open.
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
}
