package email

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
)

func sample() alert.Alert {
	return alert.Alert{
		Schema: alert.Schema, TS: time.Date(2026, 9, 11, 14, 3, 22, 0, time.UTC), Host: "web-03",
		Event: alert.EvDetected, Class: score.ClassSuspected, Mode: "remote_agent",
		User: "alice", SrcIP: "10.0.0.5", KeyFingerprint: "SHA256:Qm3k", Score: 82, Level: score.LevelAlert,
		Reasons: []clues.Clue{
			{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20, Evidence: "14 exec channels in 92s"},
			{ID: "pty.none", Category: clues.CatPTY, Weight: 15, Evidence: "0/14 sessions allocated a PTY"},
		},
		Suppressed: []score.Suppression{{Profile: "ansible", Clue: "style.abs_paths", Weight: 5}},
		SessionID:  "tr_9f31c2a7b8e4", Connections: 1,
		Window:      alert.Window{Start: time.Date(2026, 9, 11, 13, 50, 0, 0, time.UTC), End: time.Date(2026, 9, 11, 14, 5, 0, 0, time.UTC), Execs: 14},
		ActionsHint: "Ask alice whether an AI tool is driving this key.",
	}
}

type fakeTransport struct {
	from string
	to   []string
	msg  []byte
	err  error
}

func (f *fakeTransport) Send(_ context.Context, from string, to []string, msg []byte) error {
	f.from, f.to, f.msg = from, to, msg
	return f.err
}

func TestComposeViaTransport(t *testing.T) {
	ft := &fakeTransport{}
	s, err := New(Options{From: "whotyped@example.org", To: []string{"sec@example.org", "ops@example.org"}, Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "email" {
		t.Fatalf("name %q", s.Name())
	}
	if err := s.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if ft.from != "whotyped@example.org" || len(ft.to) != 2 {
		t.Fatalf("envelope %q %v", ft.from, ft.to)
	}
	msg := string(ft.msg)
	headers, body, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body separator:\n%s", msg)
	}
	for _, want := range []string{
		"Subject: [whotyped] alert agent_detected user=alice host=web-03",
		"From: whotyped@example.org",
		"To: sec@example.org, ops@example.org",
		"Content-Type: text/plain; charset=utf-8",
		"X-Whotyped-Event: agent_detected",
	} {
		if !strings.Contains(headers, want+"\r\n") {
			t.Fatalf("missing header %q in:\n%s", want, headers)
		}
	}
	for _, want := range []string{
		"whotyped agent_detected on web-03",
		"Level:     alert (score 82)",
		"User:      alice",
		"Key:       SHA256:Qm3k",
		"Agent:     -",
		"  - rhythm.burst (20): 14 exec channels in 92s",
		"  - pty.none (15): 0/14 sessions allocated a PTY",
		"  - style.abs_paths (5) by profile ansible",
		"14 execs, 1 connections",
		"Ask alice whether an AI tool is driving this key.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing body text %q in:\n%s", want, body)
		}
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Fatal("bare LF in message")
	}
}

func TestHeaderInjectionStripped(t *testing.T) {
	a := sample()
	a.User = "alice\r\nBcc: attacker@example.org"
	msg := string(Compose("a@b", []string{"c@d"}, a))
	headers, _, _ := strings.Cut(msg, "\r\n\r\n")
	if strings.Contains(headers, "\r\nBcc:") {
		t.Fatalf("header injected:\n%s", headers)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{From: "a@b", To: []string{"c@d"}}); err == nil {
		t.Fatal("host required")
	}
	if _, err := New(Options{Host: "h", To: []string{"c@d"}}); err == nil {
		t.Fatal("from required")
	}
	if _, err := New(Options{Host: "h", From: "a@b"}); err == nil {
		t.Fatal("to required")
	}
}

// scriptedSMTP is a minimal SMTP server that records the conversation.
type scriptedSMTP struct {
	ln       net.Listener
	mu       sync.Mutex
	lines    []string
	data     string
	rejectAt string // command whose reply is a 4xx (transient)
}

func newScriptedSMTP(t *testing.T) *scriptedSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptedSMTP{ln: ln}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *scriptedSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *scriptedSMTP) handle(conn net.Conn) {
	defer conn.Close()
	r := textproto.NewReader(bufio.NewReader(conn))
	w := bufio.NewWriter(conn)
	say := func(line string) { w.WriteString(line + "\r\n"); w.Flush() }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadLine()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.lines = append(s.lines, line)
		reject := s.rejectAt
		s.mu.Unlock()
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		if reject != "" && verb == reject {
			say("451 try again later")
			continue
		}
		switch verb {
		case "EHLO", "HELO":
			say("250-fake")
			say("250-AUTH PLAIN")
			say("250 8BITMIME")
		case "AUTH":
			say("235 ok")
		case "MAIL", "RCPT":
			say("250 ok")
		case "DATA":
			say("354 go")
			var body strings.Builder
			for {
				l, err := r.ReadLine()
				if err != nil {
					return
				}
				if l == "." {
					break
				}
				body.WriteString(l + "\n")
			}
			s.mu.Lock()
			s.data = body.String()
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 nope")
		}
	}
}

func (s *scriptedSMTP) opts() Options {
	return Options{Host: "127.0.0.1", Port: s.ln.Addr().(*net.TCPAddr).Port, From: "whotyped@example.org", To: []string{"sec@example.org"},
		DisableStartTLS: true, Timeout: 3 * time.Second}
}

func TestSMTPTransportConversation(t *testing.T) {
	srv := newScriptedSMTP(t)
	t.Setenv("WT_SMTP_USER", "bot")
	t.Setenv("WT_SMTP_PASS", "secret")
	o := srv.opts()
	o.UsernameEnv, o.PasswordEnv = "WT_SMTP_USER", "WT_SMTP_PASS"
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	joined := strings.Join(srv.lines, "\n")
	for _, want := range []string{"AUTH PLAIN AGJvdABzZWNyZXQ=", "MAIL FROM:<whotyped@example.org>", "RCPT TO:<sec@example.org>", "DATA", "QUIT"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("conversation missing %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(srv.data, "Subject: [whotyped] alert agent_detected user=alice host=web-03") ||
		!strings.Contains(srv.data, "rhythm.burst (20)") {
		t.Fatalf("data:\n%s", srv.data)
	}
}

func TestSMTPTransientReply(t *testing.T) {
	srv := newScriptedSMTP(t)
	srv.rejectAt = "MAIL"
	s, err := New(srv.opts())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), sample())
	if !errors.Is(err, alert.ErrTransient) {
		t.Fatalf("451 should be transient, got %v", err)
	}
}

func TestSMTPDialFailureIsTransient(t *testing.T) {
	o := Options{Host: "127.0.0.1", Port: 1, From: "a@b", To: []string{"c@d"}, DisableStartTLS: true, Timeout: time.Second}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sample()); !errors.Is(err, alert.ErrTransient) {
		t.Fatalf("dial failure should be transient, got %v", err)
	}
}

func TestSMTPRequiresStartTLSByDefault(t *testing.T) {
	srv := newScriptedSMTP(t) // does not advertise STARTTLS
	o := srv.opts()
	o.DisableStartTLS = false
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), sample())
	if err == nil || errors.Is(err, alert.ErrTransient) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected permanent STARTTLS error, got %v", err)
	}
}

// TestErrorsNeverCarryCredentials: a failed SMTP conversation is logged by
// the dispatcher; the error must name the server (host:port, operator
// config) and the step, never the password or username from the environment.
func TestErrorsNeverCarryCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	port, _ := strconv.Atoi(portStr)
	t.Setenv("WT_TEST_SMTP_USER", "alerts@example.test")
	t.Setenv("WT_TEST_SMTP_PASS", "hunter2-SECRET")
	s, err := New(Options{Host: host, Port: port, From: "a@b", To: []string{"c@d"},
		UsernameEnv: "WT_TEST_SMTP_USER", PasswordEnv: "WT_TEST_SMTP_PASS", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), alert.Alert{Schema: alert.Schema, Event: alert.EvDetected, Level: score.LevelAlert})
	if err == nil {
		t.Fatal("expected a dial error")
	}
	msg := err.Error()
	for _, secret := range []string{"hunter2-SECRET", "alerts@example.test", "WT_TEST_SMTP_PASS"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error leaks %q: %s", secret, msg)
		}
	}
	if !strings.Contains(msg, "email: dial "+ln.Addr().String()) || !errors.Is(err, alert.ErrTransient) {
		t.Fatalf("error should name the server and be transient: %s", msg)
	}
}
