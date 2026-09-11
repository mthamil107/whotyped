//go:build linux

package sshlog

import (
	"os"
	"syscall"
)

// sameFile reports whether two stat results describe the same inode on the
// same device; a rename-rotated log fails this and gets reopened.
func sameFile(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return os.SameFile(a, b)
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
}
