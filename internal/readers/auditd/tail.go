package auditd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

// lineBuffer splits a byte stream into lines, holding a partial last line
// until its newline arrives. Shared by the file tailer and the socket source.
type lineBuffer struct {
	partial []byte
}

// push appends data and returns the complete lines it contains (without the
// trailing newline or carriage return).
func (b *lineBuffer) push(data []byte) []string {
	var lines []string
	if len(b.partial) > 0 {
		data = append(b.partial, data...)
		b.partial = nil
	}
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, string(bytes.TrimRight(data[:i], "\r")))
		data = data[i+1:]
	}
	if len(data) > 0 {
		b.partial = append([]byte(nil), data...)
	}
	return lines
}

// FileTail follows an audit.log file: resumes at Offset when the inode still
// matches, polls for appended data, and follows rotation (new inode on Linux,
// size shrink elsewhere).
type FileTail struct {
	Path      string
	FromStart bool   // when not resuming: read from the beginning instead of the end
	Offset    int64  // resume offset (bytes through the last complete line)
	Inode     uint64 // inode the offset belongs to; 0 on non-Linux
	Poll      time.Duration
	Now       func() time.Time
	// Parser receives the lines; a default one is created when nil.
	Parser *Parser

	mu     sync.Mutex
	offset int64  // bytes consumed through the last complete line
	inode  uint64 // inode of the file offset refers to
	pos    int64  // read position in the current file (offset + partial line)
	buf    lineBuffer
}

func (t *FileTail) poll() time.Duration {
	if t.Poll > 0 {
		return t.Poll
	}
	return 250 * time.Millisecond
}

func (t *FileTail) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *FileTail) parser() *Parser {
	if t.Parser == nil {
		t.Parser = NewParser()
		t.Parser.Now = t.Now
	}
	return t.Parser
}

// Position returns the offset of the last complete line consumed and the
// inode of the file it belongs to, for state persistence.
func (t *FileTail) Position() (offset int64, inode uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offset, t.inode
}

// reset positions the tailer at start in a (re)opened file.
func (t *FileTail) reset(start int64, inode uint64) {
	t.mu.Lock()
	t.offset, t.inode, t.pos = start, inode, start
	t.buf = lineBuffer{}
	t.mu.Unlock()
}

// Run tails the file until ctx is done. It returns an error only when the
// file cannot be opened initially; later disappearance (rotation window) is
// waited out.
func (t *FileTail) Run(ctx context.Context, out chan<- event.Event) error {
	p := t.parser()
	emit := func(evs []event.Event) bool {
		for _, ev := range evs {
			select {
			case out <- ev:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}

	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	ino := fileInode(fi)

	// State continuity: resume only when the offset belongs to this very
	// file. If the saved inode now belongs to audit.log.1 the rotation
	// happened while we were down: finish that file first.
	start := int64(0)
	if !t.FromStart {
		start = fi.Size()
	}
	switch {
	case t.Offset > 0 && t.Inode == ino && t.Offset <= fi.Size():
		start = t.Offset
	case t.Offset > 0 && t.Inode != 0 && t.Inode != ino:
		if !emit(t.drainRotated(t.Path+".1", t.Inode, t.Offset)) {
			f.Close()
			return nil
		}
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	t.reset(start, ino)

	ticker := time.NewTicker(t.poll())
	defer ticker.Stop()
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	readBuf := make([]byte, 64<<10)
	for {
		if f != nil {
			evs, err := t.drain(f, readBuf, p)
			if !emit(evs) {
				return nil
			}
			if err != nil && !errors.Is(err, io.EOF) {
				// Transient read error: reopen on the next tick.
				f.Close()
				f = nil
			}
		}
		if !holdOpen && f != nil {
			// Windows cannot rename a file that is held open, so release it
			// between polls; the offset lets us pick up where we left off.
			f.Close()
			f = nil
		}
		if !emit(p.Flush(t.now())) {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		prevOff, prevIno := t.Position()
		oldPartial := t.buf.partial
		nf, rotated, err := t.reopenIfNeeded(f)
		if err != nil {
			continue // file missing right now (rotation window): keep waiting
		}
		if rotated {
			var evs []event.Event
			if f != nil {
				// Linux: the old handle still reads the renamed file. Finish it.
				evs, _ = t.drainWith(f, readBuf, p, &lineBuffer{partial: oldPartial})
				f.Close()
			} else {
				// No handle held (non-Linux): the tail of the old file is in ".1".
				evs = t.drainRotated(t.Path+".1", prevIno, prevOff)
			}
			if !emit(evs) {
				nf.Close()
				return nil
			}
		}
		f = nf
	}
}

// drain reads everything currently available from f, feeding complete lines
// to the parser and advancing the position past each newline.
func (t *FileTail) drain(f *os.File, readBuf []byte, p *Parser) ([]event.Event, error) {
	return t.drainWith(f, readBuf, p, nil)
}

// drainWith is drain with an explicit line buffer; nil means the tailer's own
// buffer (and position tracking). A private buffer is used to finish a
// rotated file whose position no longer matters.
func (t *FileTail) drainWith(f *os.File, readBuf []byte, p *Parser, lb *lineBuffer) ([]event.Event, error) {
	track := lb == nil
	if track {
		lb = &t.buf
	}
	var evs []event.Event
	for {
		n, err := f.Read(readBuf)
		if n > 0 {
			for _, line := range lb.push(readBuf[:n]) {
				evs = append(evs, p.Feed(line)...)
			}
			if track {
				// The offset only counts complete lines so that a restart
				// re-reads a partial line instead of losing it.
				t.mu.Lock()
				t.pos += int64(n)
				t.offset = t.pos - int64(len(lb.partial))
				t.mu.Unlock()
			}
		}
		if err != nil {
			return evs, err
		}
		if n == 0 {
			return evs, io.EOF
		}
	}
}

// reopenIfNeeded stats the path and decides whether the file was replaced
// (different inode) or truncated (size below our offset). It returns the
// handle to read from next, which is f itself when nothing changed and a
// handle is held.
func (t *FileTail) reopenIfNeeded(f *os.File) (*os.File, bool, error) {
	fi, err := os.Stat(t.Path)
	if err != nil {
		return f, false, err
	}
	ino := fileInode(fi)
	offset, curIno := t.Position()
	rotated := (ino != 0 && ino != curIno) || fi.Size() < offset
	if !rotated && f != nil {
		return f, false, nil
	}
	nf, err := os.Open(t.Path)
	if err != nil {
		return f, false, err
	}
	start := int64(0)
	if !rotated {
		// Same file, reopened after being released: continue at the last
		// complete line (the partial line is re-read).
		start = offset
	}
	if _, err := nf.Seek(start, io.SeekStart); err != nil {
		nf.Close()
		return f, false, err
	}
	t.reset(start, ino)
	return nf, rotated, nil
}

// drainRotated reads audit.log.1 from offset when it is the file we were
// tailing before (inode match; on non-Linux both are 0 and size is the only
// check), so no lines are lost across the rotation.
func (t *FileTail) drainRotated(path string, inode uint64, offset int64) []event.Event {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fileInode(fi) != inode || fi.Size() < offset {
		return nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	p := t.parser()
	var evs []event.Event
	buf := make([]byte, 64<<10)
	lb := lineBuffer{}
	for {
		n, err := f.Read(buf)
		for _, line := range lb.push(buf[:n]) {
			evs = append(evs, p.Feed(line)...)
		}
		if err != nil || n == 0 {
			break
		}
	}
	if len(lb.partial) > 0 {
		evs = append(evs, p.Feed(string(lb.partial))...)
	}
	return evs
}
