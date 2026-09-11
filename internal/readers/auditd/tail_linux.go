//go:build linux

package auditd

import (
	"os"
	"syscall"
)

// holdOpen keeps the audit.log handle open between polls so a renamed
// (rotated) file can still be drained through it.
const holdOpen = true

// fileInode returns the inode number, the key that tells a rotated file from
// the one we were reading.
func fileInode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
