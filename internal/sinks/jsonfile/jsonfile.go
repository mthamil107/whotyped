// Package jsonfile appends alerts to a JSON Lines file with size-based rotation.
package jsonfile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mthamil107/whotyped/internal/alert"
)

// Options configures the sink.
type Options struct {
	Path      string
	MaxSizeMB int  // rotate when the file would exceed this; 0 disables rotation
	Keep      int  // rotated siblings to keep (.1 is newest); 0 discards on rotation
	Fsync     bool // fsync after every line (durable, slower)
}

// Sink writes one JSON object per line. Safe for concurrent Send.
type Sink struct {
	o        Options
	maxBytes int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

// New creates the parent directory (0750) and opens the file (0640, append).
func New(o Options) (*Sink, error) {
	if o.Path == "" {
		return nil, errors.New("jsonfile: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(o.Path), 0o750); err != nil {
		return nil, fmt.Errorf("jsonfile: create dir: %w", err)
	}
	s := &Sink{o: o, maxBytes: int64(o.MaxSizeMB) << 20}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

// Name implements alert.Sink.
func (s *Sink) Name() string { return "jsonfile" }

// Send appends a; the whole line is written in one call so readers never see
// a torn record on POSIX filesystems.
func (s *Sink) Send(_ context.Context, a alert.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("jsonfile: marshal: %w", err)
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		if err := s.open(); err != nil {
			return err
		}
	}
	// Rotate before the write that would cross the limit; an oversized single
	// line into an empty file is written anyway rather than looping.
	if s.maxBytes > 0 && s.size > 0 && s.size+int64(len(b)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.f.Write(b)
	s.size += int64(n)
	if err != nil {
		return fmt.Errorf("jsonfile: write: %w", err)
	}
	if s.o.Fsync {
		if err := s.f.Sync(); err != nil {
			return fmt.Errorf("jsonfile: fsync: %w", err)
		}
	}
	return nil
}

// Close flushes and closes the file. Send after Close reopens it.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Sync()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	s.f = nil
	return err
}

// open appends to the alerts file. The daemon runs as root and the path is
// operator-configured, but the directory may be shared: a symlink planted at
// the path must not redirect alert writes (O_NOFOLLOW on Linux, an explicit
// Lstat elsewhere) and an existing non-regular target (FIFO, device) is
// refused rather than written to.
func (s *Sink) open() error {
	if st, err := os.Lstat(s.o.Path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("jsonfile: open: %s is a symlink; refusing to follow it", s.o.Path)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("jsonfile: open: %s is not a regular file (%s)", s.o.Path, st.Mode().Type())
		}
	}
	f, err := openAppend(s.o.Path)
	if err != nil {
		return fmt.Errorf("jsonfile: open: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("jsonfile: stat: %w", err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("jsonfile: open: %s is not a regular file", s.o.Path)
	}
	s.f, s.size = f, st.Size()
	return nil
}

// rotate shifts path.N -> path.N+1, path -> path.1 and reopens a fresh file.
// The file is closed first because Windows refuses to rename open files.
func (s *Sink) rotate() error {
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
	p := s.o.Path
	if s.o.Keep <= 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("jsonfile: rotate: %w", err)
		}
		return s.open()
	}
	_ = os.Remove(rotated(p, s.o.Keep))
	for i := s.o.Keep - 1; i >= 1; i-- {
		if err := os.Rename(rotated(p, i), rotated(p, i+1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("jsonfile: rotate: %w", err)
		}
	}
	if err := os.Rename(p, rotated(p, 1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("jsonfile: rotate: %w", err)
	}
	return s.open()
}

func rotated(path string, n int) string { return path + "." + strconv.Itoa(n) }

// ReadAll returns alerts from path and its rotated siblings (path.1, path.2, …)
// with TS >= since (zero since means everything), oldest first. Malformed or
// truncated lines are skipped, not fatal, so a crash mid-write cannot hide a
// week of history from `whotyped report`. A missing main file is not an error.
func ReadAll(path string, since time.Time) ([]alert.Alert, error) {
	files, err := siblings(path)
	if err != nil {
		return nil, err
	}
	var out []alert.Alert
	for _, f := range files {
		as, err := readFile(f, since)
		if err != nil {
			return nil, err
		}
		out = append(out, as...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out, nil
}

// siblings lists rotated files newest-number-first (oldest data first), then path.
func siblings(path string) ([]string, error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("jsonfile: read dir: %w", err)
	}
	var nums []int
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), base+".")
		if !ok || e.IsDir() {
			continue
		}
		if n, err := strconv.Atoi(suffix); err == nil && n > 0 {
			nums = append(nums, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	files := make([]string, 0, len(nums)+1)
	for _, n := range nums {
		files = append(files, rotated(path, n))
	}
	if _, err := os.Stat(path); err == nil {
		files = append(files, path)
	}
	return files, nil
}

func readFile(path string, since time.Time) ([]alert.Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("jsonfile: open %s: %w", path, err)
	}
	defer f.Close()
	var out []alert.Alert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var a alert.Alert
		if err := json.Unmarshal(line, &a); err != nil || a.Schema == "" {
			continue
		}
		if !since.IsZero() && a.TS.Before(since) {
			continue
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("jsonfile: read %s: %w", path, err)
	}
	return out, nil
}
