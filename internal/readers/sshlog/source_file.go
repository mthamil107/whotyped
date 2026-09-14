package sshlog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
)

// maxLineBytes bounds a single log line; longer lines are dropped rather
// than growing memory (sshd never legitimately logs lines this long).
const maxLineBytes = 1 << 20

// FileSource tails a syslog-format file (/var/log/auth.log, /var/log/secure)
// by polling: no inotify, so it works over NFS and in containers. Rotation
// (rename or copytruncate) is detected by comparing the open file against
// the path every poll and the file is reopened from the start.
type FileSource struct {
	Path      string
	FromStart bool          // read existing content instead of seeking to the end
	Poll      time.Duration // default 250ms
	Now       func() time.Time
	Logf      func(format string, args ...any)
}

func (s *FileSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *FileSource) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Run follows the file until ctx is done. It returns an error only if the
// file cannot be opened at start; later disappearance (mid-rotation) is
// tolerated and retried.
func (s *FileSource) Run(ctx context.Context, out chan<- event.Event) error {
	poll := s.Poll
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return err
	}
	if !s.FromStart {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return err
		}
	}
	defer func() { f.Close() }()

	openFI, _ := f.Stat()
	rd := bufio.NewReaderSize(f, 64*1024)
	var pending []byte // partial line waiting for its newline

	timer := time.NewTimer(poll)
	defer timer.Stop()

	for {
		if err := s.drain(ctx, rd, &pending, out); err != nil {
			return err
		}
		timer.Reset(poll)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		offset, _ := f.Seek(0, io.SeekCurrent)
		cur, err := os.Stat(s.Path)
		if err != nil {
			// Renamed away and not yet recreated; keep the old fd for now.
			continue
		}
		switch {
		case openFI != nil && !sameFile(openFI, cur):
			// Rotated by rename: finish the old file, then start the new one.
			if err := s.drain(ctx, rd, &pending, out); err != nil {
				return err
			}
			nf, err := os.Open(s.Path)
			if err != nil {
				continue
			}
			f.Close()
			f, openFI = nf, cur
			rd.Reset(f)
			pending = pending[:0]
			s.logf("sshlog: %s rotated, reopened", s.Path)
		case cur.Size() < offset:
			// Truncated in place (copytruncate).
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			rd.Reset(f)
			pending = pending[:0]
			s.logf("sshlog: %s truncated, rereading from start", s.Path)
		}
	}
}

// drain reads every complete line available now and emits its event.
// A trailing partial line is kept in *pending until the rest arrives.
func (s *FileSource) drain(ctx context.Context, rd *bufio.Reader, pending *[]byte, out chan<- event.Event) error {
	for {
		chunk, err := rd.ReadSlice('\n')
		if len(chunk) > 0 {
			if len(*pending)+len(chunk) <= maxLineBytes {
				*pending = append(*pending, chunk...)
			} else {
				*pending = append((*pending)[:0], 0) // poison: line too long, drop it
			}
		}
		switch {
		case err == nil:
			line := *pending
			*pending = (*pending)[:0]
			if len(line) > 0 && line[0] == 0 {
				continue
			}
			if err := s.emit(ctx, string(line), out); err != nil {
				return err
			}
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil
		default:
			return err
		}
	}
}

func (s *FileSource) emit(ctx context.Context, line string, out chan<- event.Event) error {
	ev, ok := parseAny(line, s.now())
	if !ok {
		return nil
	}
	select {
	case out <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parseAny handles both syslog text and journalctl JSON lines so that a
// `journalctl -o json > dump` file replays as well as auth.log does.
func parseAny(line string, now time.Time) (event.Event, bool) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return event.Event{}, false
	}
	var (
		l  Line
		ok bool
	)
	if line[0] == '{' {
		l, ok = ParseJournalJSON([]byte(line))
		if ok && l.TS.IsZero() {
			l.TS = now
		}
	} else {
		l, ok = ParseSyslogLine(line, now)
	}
	if !ok {
		return event.Event{}, false
	}
	return ParseMessage(l)
}

// ReplayReader parses every line of r (syslog text or journalctl JSON) and
// returns the events in file order. Used by tests and by `run --once` over
// an existing auth.log.
func ReplayReader(r io.Reader, now time.Time) []event.Event {
	var events []event.Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		if ev, ok := parseAny(string(bytes.TrimSpace(sc.Bytes())), now); ok {
			events = append(events, ev)
		}
	}
	return events
}
