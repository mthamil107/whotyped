package simulate

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScenariosMatchDataset guards the embedded copies: every file under
// scenarios/ must be byte-identical to testdata/dataset, and every dataset
// scenario must be embedded. Fix by re-copying from testdata/dataset.
func TestScenariosMatchDataset(t *testing.T) {
	dataset := filepath.Join("..", "..", "testdata", "dataset")
	entries, err := os.ReadDir(dataset)
	if err != nil {
		t.Fatalf("dataset dir: %v", err)
	}
	want := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			want[e.Name()] = true
		}
	}
	got := map[string]bool{}
	for _, name := range List() {
		got[name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("scenario %s exists in testdata/dataset but is not embedded; copy it to internal/simulate/scenarios/%s", name, name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("embedded scenario %s has no source in testdata/dataset", name)
		}
	}
	err = fs.WalkDir(Scenarios, "scenarios", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(path, "scenarios/")
		embedded, err := fs.ReadFile(Scenarios, path)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(filepath.Join(dataset, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		if !bytes.Equal(embedded, src) {
			t.Errorf("%s drifted from testdata/dataset; re-copy the file", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
