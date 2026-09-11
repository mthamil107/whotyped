//go:build linux

package main

import (
	"io/fs"
	"os"
)

// platformRoot is the real filesystem, so --sshd-config only replaces the
// one file and every other probe still sees the host.
func platformRoot() fs.FS { return os.DirFS("/") }
