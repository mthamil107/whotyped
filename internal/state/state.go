// Package state persists the daemon's resumable state (open tracks, reader
// cursors, dedupe keys) to a JSON file with atomic replace semantics.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mthamil107/whotyped/internal/session"
)

// Version is the current on-disk format. Files with a higher version are
// refused rather than half-read.
const Version = 1

// State is everything needed to resume after a restart without re-alerting.
type State struct {
	Version       int                  `json:"version"`
	SavedAt       time.Time            `json:"saved_at"`
	Tracks        []*session.Track     `json:"tracks"`
	JournalCursor string               `json:"journal_cursor,omitempty"`
	AuditOffset   int64                `json:"audit_offset,omitempty"`
	AuditInode    uint64               `json:"audit_inode,omitempty"`
	Dedupe        map[string]time.Time `json:"dedupe,omitempty"`
}

// Load reads path. A missing file yields an empty State and no error; a
// corrupt or newer-version file yields an error and never panics.
func Load(path string) (State, error) {
	empty := State{Version: Version, Dedupe: map[string]time.Time{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return empty, nil
		}
		return empty, fmt.Errorf("state: read %s: %w", path, err)
	}
	if len(b) == 0 {
		return empty, nil
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return empty, fmt.Errorf("state: parse %s: %w", path, err)
	}
	if s.Version > Version {
		return empty, fmt.Errorf("state: %s is version %d, this build reads up to %d", path, s.Version, Version)
	}
	if s.Dedupe == nil {
		s.Dedupe = map[string]time.Time{}
	}
	// Drop nil entries so callers can range without nil checks.
	tracks := s.Tracks[:0]
	for _, t := range s.Tracks {
		if t != nil {
			tracks = append(tracks, t)
		}
	}
	s.Tracks = tracks
	return s, nil
}

// Save writes s atomically: temp file in the same directory, fsync, rename.
// The file is 0600 and its directory is created 0750 if missing.
func Save(path string, s State) error {
	s.Version = Version
	if s.SavedAt.IsZero() {
		s.SavedAt = time.Now()
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("state: marshal: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("state: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("state: temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return fmt.Errorf("state: chmod: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		cleanup()
		return fmt.Errorf("state: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("state: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("state: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("state: rename: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable on POSIX filesystems. Windows has no
// directory fsync, so failures are ignored everywhere.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}

// Run saves snapshot() every `every` (default 30s) and once more when ctx is
// done, returning that final save's error. Periodic failures are logged and
// retried on the next tick; a persistent failure never stops the daemon.
func Run(ctx context.Context, path string, every time.Duration, snapshot func() State) error {
	if every <= 0 {
		every = 30 * time.Second
	}
	log := slog.Default().With("component", "state", "path", path)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if err := Save(path, snapshot()); err != nil {
				log.Warn("periodic save failed", "err", err)
			}
		case <-ctx.Done():
			err := Save(path, snapshot())
			if err != nil {
				log.Error("final save failed", "err", err)
			}
			return err
		}
	}
}
