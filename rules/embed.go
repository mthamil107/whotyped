// Package rules embeds the default rule packs shipped with whotyped.
//
// The canonical YAML lives in this top-level directory so that operators can
// read it in the repository and copy it into an override directory; Go's
// embed cannot reach a parent directory, hence this tiny package. The loader
// in internal/rules reads FS and merges override directories on top.
package rules

import "embed"

// FS holds every *.yaml rule pack and allowlist file in this directory.
//
//go:embed *.yaml
var FS embed.FS

// Files lists the embedded default pack file names in load order.
var Files = []string{
	"agents.yaml",
	"banners.yaml",
	"styles.yaml",
	"apihosts.yaml",
	"allowlist.yaml",
}
