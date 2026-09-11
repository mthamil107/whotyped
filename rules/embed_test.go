package rules

import (
	"io/fs"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEmbeddedFilesPresent guards against a pack being renamed or dropped
// from the embed glob without Files being updated.
func TestEmbeddedFilesPresent(t *testing.T) {
	seen := map[string]bool{}
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		seen[e.Name()] = true
	}
	for _, name := range Files {
		if !seen[name] {
			t.Errorf("embedded file %q missing", name)
		}
	}
	if len(entries) != len(Files) {
		t.Errorf("embedded %d files, Files lists %d; keep them in sync", len(entries), len(Files))
	}
}

// TestEmbeddedFilesAreYAML checks every pack parses and carries a schema.
func TestEmbeddedFilesAreYAML(t *testing.T) {
	for _, name := range Files {
		data, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			Schema  string `yaml:"schema"`
			Version string `yaml:"version"`
		}
		if err := yaml.Unmarshal(data, &head); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if head.Schema != "whotyped.rules.v1" && head.Schema != "whotyped.allowlist.v1" {
			t.Errorf("%s: unexpected schema %q", name, head.Schema)
		}
		if head.Version == "" {
			t.Errorf("%s: missing version", name)
		}
	}
}
