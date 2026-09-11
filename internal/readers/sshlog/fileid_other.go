//go:build !linux

package sshlog

import "os"

// sameFile uses the portable identity check (on Windows: volume serial +
// file index). A copytruncate rotation keeps the identity; that case is
// caught by the size comparison in FileSource.Run.
func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b)
}
