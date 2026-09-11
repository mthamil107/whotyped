// Package version carries the build identity injected by the linker:
//
//	-ldflags "-X github.com/whotyped/whotyped/internal/version.Version=v0.1.0 ..."
//
// The defaults describe a `go build` or `go run` straight from the tree.
package version

import "runtime"

// Set via -ldflags -X; see Makefile and .goreleaser.yaml.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String renders the one-line form printed by `whotyped version`.
func String() string {
	return "whotyped " + Version + " (" + Commit + ", " + Date + ", " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
