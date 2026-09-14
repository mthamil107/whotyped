package auditd

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/mthamil107/whotyped/internal/event"
)

// SocketSource reads newline-delimited audit records from the audisp af_unix
// plugin socket (audisp-af_unix, default /run/audit/audispd_events). It
// reconnects with backoff when the socket goes away.
type SocketSource struct {
	Path string
	Now  func() time.Time
	// Parser receives the lines; a default one is created when nil.
	Parser *Parser

	// dial is overridable for tests; nil means the platform dialer.
	dial func(path string) (net.Conn, error)
	// maxBackoff caps the reconnect delay; zero means 30s.
	maxBackoff time.Duration
}

func (s *SocketSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SocketSource) parser() *Parser {
	if s.Parser == nil {
		s.Parser = NewParser()
		s.Parser.Now = s.Now
	}
	return s.Parser
}

// Run connects, reads lines until the connection drops, then reconnects with
// exponential backoff (1s doubling to 30s) until ctx is done. On platforms
// without the audisp socket it returns readers.ErrUnsupportedPlatform.
func (s *SocketSource) Run(ctx context.Context, out chan<- event.Event) error {
	dial := s.dial
	if dial == nil {
		dial = dialAudisp
	}
	p := s.parser()
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
	maxBackoff := s.maxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	initial := time.Second
	if initial > maxBackoff {
		initial = maxBackoff
	}
	backoff := initial
	for {
		conn, err := dial(s.Path)
		if err != nil {
			if unsupported(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = initial
		s.readConn(ctx, conn, p, emit)
		conn.Close()
		if ctx.Err() != nil {
			return nil
		}
	}
}

// readConn pumps one connection into the parser. A short read deadline
// doubles as the Flush tick so the last event of a burst is not held back.
func (s *SocketSource) readConn(ctx context.Context, conn net.Conn, p *Parser, emit func([]event.Event) bool) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	buf := make([]byte, 64<<10)
	lb := lineBuffer{}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			var evs []event.Event
			for _, line := range lb.push(buf[:n]) {
				evs = append(evs, p.Feed(line)...)
			}
			if !emit(evs) {
				return
			}
		}
		if !emit(p.Flush(s.now())) {
			return
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && ctx.Err() == nil {
				continue
			}
			return
		}
	}
}

// unsupported reports the platform stub's error so Run gives up instead of
// retrying forever.
func unsupported(err error) bool {
	return errors.Is(err, errUnsupported)
}

// socketExists reports whether path exists and is a unix socket (used by the
// reader's "auto" source selection).
func socketExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}
