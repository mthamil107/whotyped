//go:build !linux

package auditd

import "os"

// holdOpen is false off Linux: Windows refuses to rename a file that is held
// open, so the tailer releases the handle between polls.
const holdOpen = false

// fileInode has no portable equivalent; rotation is detected by size shrink.
func fileInode(os.FileInfo) uint64 { return 0 }
