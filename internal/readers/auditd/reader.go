package auditd

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/readers"
)

// Default locations.
const (
	DefaultFile   = "/var/log/audit/audit.log"
	DefaultSocket = "/run/audit/audispd_events"
)

// Options configures the auditd reader.
type Options struct {
	Source       string // auto | file | socket
	File         string // audit.log path; DefaultFile when empty
	Socket       string // audisp af_unix socket; DefaultSocket when empty
	FromStart    bool   // file source: read from the beginning when not resuming
	ResumeOffset int64  // file source: offset saved in state.json
	ResumeInode  uint64 // file source: inode the offset belongs to
	Now          func() time.Time
}

// Reader implements readers.Reader over audit.log or the audisp socket.
type Reader struct {
	opts   Options
	parser *Parser
	tail   *FileTail
	sock   *SocketSource
}

var _ readers.Reader = (*Reader)(nil)

// New builds a Reader; nothing is opened until Run.
func New(opts Options) *Reader {
	if opts.Source == "" {
		opts.Source = "auto"
	}
	if opts.File == "" {
		opts.File = DefaultFile
	}
	if opts.Socket == "" {
		opts.Socket = DefaultSocket
	}
	p := NewParser()
	p.Now = opts.Now
	r := &Reader{opts: opts, parser: p}
	r.tail = &FileTail{
		Path:      opts.File,
		FromStart: opts.FromStart,
		Offset:    opts.ResumeOffset,
		Inode:     opts.ResumeInode,
		Now:       opts.Now,
		Parser:    p,
	}
	r.sock = &SocketSource{Path: opts.Socket, Now: opts.Now, Parser: p}
	return r
}

// Name implements readers.Reader.
func (r *Reader) Name() string { return "auditd" }

// Run implements readers.Reader. Source "auto" prefers the audisp socket when
// it exists (no file permissions or rotation to worry about) and falls back
// to tailing audit.log.
func (r *Reader) Run(ctx context.Context, out chan<- event.Event) error {
	switch r.source() {
	case "socket":
		return r.sock.Run(ctx, out)
	default:
		return r.tail.Run(ctx, out)
	}
}

func (r *Reader) source() string {
	switch r.opts.Source {
	case "socket", "file":
		return r.opts.Source
	}
	if socketExists(r.opts.Socket) {
		return "socket"
	}
	return "file"
}

// Position returns the file offset/inode to persist. Both are 0 for the
// socket source, which has no resumable position.
func (r *Reader) Position() (offset int64, inode uint64) {
	return r.tail.Position()
}

// Stats returns parser counters.
func (r *Reader) Stats() Stats { return r.parser.Stats() }

// Replay parses a whole audit log (fixture or `run --once` input) and returns
// every event in order. Lines may be up to 8 MiB (chunked EXECVE records).
func Replay(rd io.Reader) []event.Event {
	p := NewParser()
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	var evs []event.Event
	for sc.Scan() {
		evs = append(evs, p.Feed(sc.Text())...)
	}
	return append(evs, p.FlushAll()...)
}
