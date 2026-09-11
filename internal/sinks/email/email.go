// Package email sends one plain-text message per alert over SMTP with STARTTLS.
package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
)

// Options configures the sink. Credentials are looked up in the environment
// at send time so a rotated secret takes effect without a restart.
type Options struct {
	Host string
	Port int // default 587
	From string
	To   []string

	UsernameEnv string // env var holding the SMTP username; "" = no auth
	PasswordEnv string // env var holding the SMTP password

	DisableStartTLS    bool          // plain SMTP; PLAIN auth then only works to localhost
	InsecureSkipVerify bool          // skip certificate verification (lab use only)
	Timeout            time.Duration // whole SMTP conversation; default 15s

	// Transport overrides the SMTP client; nil uses net/smtp. Tests use it to
	// capture the composed message.
	Transport Transport
}

// Transport delivers a finished RFC 5322 message.
type Transport interface {
	Send(ctx context.Context, from string, to []string, msg []byte) error
}

// Sink is the email alert sink.
type Sink struct {
	o  Options
	tr Transport
}

// New validates o and returns a sink.
func New(o Options) (*Sink, error) {
	if o.Host == "" && o.Transport == nil {
		return nil, errors.New("email: host is required")
	}
	if o.From == "" {
		return nil, errors.New("email: from is required")
	}
	if len(o.To) == 0 {
		return nil, errors.New("email: at least one recipient is required")
	}
	if o.Port <= 0 {
		o.Port = 587
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	tr := o.Transport
	if tr == nil {
		tr = &smtpTransport{o: o}
	}
	return &Sink{o: o, tr: tr}, nil
}

// Name implements alert.Sink.
func (s *Sink) Name() string { return "email" }

// Send composes and delivers the message.
func (s *Sink) Send(ctx context.Context, a alert.Alert) error {
	return s.tr.Send(ctx, s.o.From, s.o.To, Compose(s.o.From, s.o.To, a))
}

// Subject renders "[whotyped] <level> <event> user=<user> host=<host>".
func Subject(a alert.Alert) string {
	return fmt.Sprintf("[whotyped] %s %s user=%s host=%s", a.Level, a.Event, a.User, a.Host)
}

// Compose builds the full message (headers + body) with CRLF line endings.
func Compose(from string, to []string, a alert.Alert) []byte {
	var b strings.Builder
	hdr := func(k, v string) {
		// Strip CR/LF so a hostile username cannot inject headers.
		v = strings.NewReplacer("\r", "", "\n", "").Replace(v)
		b.WriteString(k + ": " + v + "\r\n")
	}
	hdr("From", from)
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", Subject(a)))
	ts := a.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	hdr("Date", ts.Format(time.RFC1123Z))
	hdr("Message-ID", fmt.Sprintf("<%d.%s.%s@%s>", ts.UnixNano(), a.Event, a.SessionID, hostPart(a.Host)))
	hdr("X-Whotyped-Event", a.Event)
	hdr("X-Whotyped-Level", string(a.Level))
	hdr("Auto-Submitted", "auto-generated")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(Body(a), "\n", "\r\n"))
	return []byte(b.String())
}

// Body renders the plain-text body with LF line endings.
func Body(a alert.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "whotyped %s on %s\n\n", a.Event, a.Host)
	row := func(k, v string) {
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(&b, "%-10s %s\n", k+":", v)
	}
	row("Time", a.TS.UTC().Format(time.RFC3339))
	row("Class", string(a.Class))
	row("Level", fmt.Sprintf("%s (score %d)", a.Level, a.Score))
	row("User", a.User)
	row("Source", a.SrcIP)
	row("Key", a.KeyFingerprint)
	row("Agent", a.Agent)
	row("Mode", a.Mode)
	row("Session", a.SessionID)
	if !a.Window.End.IsZero() {
		row("Window", fmt.Sprintf("%s .. %s, %d execs, %d connections",
			a.Window.Start.UTC().Format(time.RFC3339), a.Window.End.UTC().Format(time.RFC3339), a.Window.Execs, a.Connections))
	}
	if a.FreezeWindow != nil {
		row("Freeze", fmt.Sprintf("%s until %s", a.FreezeWindow.Name, a.FreezeWindow.Until.UTC().Format(time.RFC3339)))
	}
	b.WriteString("\nReasons:\n")
	if len(a.Reasons) == 0 {
		b.WriteString("  (none recorded)\n")
	}
	for _, r := range a.Reasons {
		fmt.Fprintf(&b, "  - %s (%d): %s\n", r.ID, r.Weight, r.Evidence)
	}
	if len(a.Suppressed) > 0 {
		b.WriteString("\nSuppressed by allowlist:\n")
		for _, s := range a.Suppressed {
			fmt.Fprintf(&b, "  - %s (%d) by profile %s\n", s.Clue, s.Weight, s.Profile)
		}
	}
	if a.ActionsHint != "" {
		b.WriteString("\n" + a.ActionsHint + "\n")
	}
	return b.String()
}

func hostPart(h string) string {
	if h == "" {
		return "localhost"
	}
	return h
}

// ---------------------------------------------------------------------------
// net/smtp transport

type smtpTransport struct {
	o Options
}

// Send runs one SMTP conversation: dial, EHLO, STARTTLS, AUTH PLAIN when
// credentials are configured, MAIL/RCPT/DATA, QUIT. Connection and 4xx reply
// failures are marked transient for the dispatcher's retry loop.
func (t *smtpTransport) Send(ctx context.Context, from string, to []string, msg []byte) (err error) {
	addr := net.JoinHostPort(t.o.Host, strconv.Itoa(t.o.Port))
	d := net.Dialer{Timeout: t.o.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("%w: email: dial %s: %v", alert.ErrTransient, addr, err)
	}
	deadline := time.Now().Add(t.o.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, t.o.Host)
	if err != nil {
		conn.Close()
		return classify("greeting", err)
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if !t.o.DisableStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("email: server does not offer STARTTLS (set disable_starttls to send in clear)")
		}
		if err := c.StartTLS(&tls.Config{ServerName: t.o.Host, InsecureSkipVerify: t.o.InsecureSkipVerify, MinVersion: tls.VersionTLS12}); err != nil {
			return classify("starttls", err)
		}
	}
	if t.o.UsernameEnv != "" {
		user, pass := os.Getenv(t.o.UsernameEnv), os.Getenv(t.o.PasswordEnv)
		if user == "" {
			return fmt.Errorf("email: env %s is empty; cannot authenticate", t.o.UsernameEnv)
		}
		if err := c.Auth(smtp.PlainAuth("", user, pass, t.o.Host)); err != nil {
			return classify("auth", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return classify("mail from", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return classify("rcpt to", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return classify("data", err)
	}
	if _, err := w.Write(msg); err != nil {
		return classify("write", err)
	}
	if err := w.Close(); err != nil {
		return classify("data end", err)
	}
	if err := c.Quit(); err != nil {
		// The message is accepted at this point; a noisy QUIT is not a failure.
		c.Close()
	}
	return nil
}

// classify wraps SMTP errors: 4xx replies and network errors are transient.
func classify(step string, err error) error {
	var tp *textproto.Error
	if errors.As(err, &tp) && tp.Code >= 400 && tp.Code < 500 {
		return fmt.Errorf("%w: email: %s: %v", alert.ErrTransient, step, err)
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return fmt.Errorf("%w: email: %s: %v", alert.ErrTransient, step, err)
	}
	return fmt.Errorf("email: %s: %w", step, err)
}
