//go:build !linux

package main

import "io/fs"

// platformRoot is nil off Linux: there is no /etc/ssh or /proc to probe.
func platformRoot() fs.FS { return nil }
