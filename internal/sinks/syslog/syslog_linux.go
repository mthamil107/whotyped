//go:build linux

package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	gosyslog "log/syslog"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/score"
)

type sink struct {
	w *gosyslog.Writer
}

// New connects to the local syslog daemon with the given tag and facility.
func New(tag, facility string) (alert.Sink, error) {
	tag, facility, err := normalise(tag, facility)
	if err != nil {
		return nil, err
	}
	w, err := gosyslog.New(facilityOf(facility)|gosyslog.LOG_INFO, tag)
	if err != nil {
		return nil, fmt.Errorf("syslog: connect: %w", err)
	}
	return &sink{w: w}, nil
}

func (s *sink) Name() string { return "syslog" }

// Send writes the alert JSON at the severity mapped from the level. The
// writer reconnects on its own if the daemon restarts.
func (s *sink) Send(_ context.Context, a alert.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("syslog: marshal: %w", err)
	}
	msg := string(b)
	switch a.Level {
	case score.LevelHigh:
		err = s.w.Alert(msg)
	case score.LevelAlert:
		err = s.w.Warning(msg)
	default:
		err = s.w.Info(msg)
	}
	if err != nil {
		return fmt.Errorf("%w: syslog write: %v", alert.ErrTransient, err)
	}
	return nil
}

// Close releases the daemon connection.
func (s *sink) Close() error { return s.w.Close() }

func facilityOf(name string) gosyslog.Priority {
	switch name {
	case "kern":
		return gosyslog.LOG_KERN
	case "user":
		return gosyslog.LOG_USER
	case "mail":
		return gosyslog.LOG_MAIL
	case "daemon":
		return gosyslog.LOG_DAEMON
	case "syslog":
		return gosyslog.LOG_SYSLOG
	case "lpr":
		return gosyslog.LOG_LPR
	case "news":
		return gosyslog.LOG_NEWS
	case "uucp":
		return gosyslog.LOG_UUCP
	case "cron":
		return gosyslog.LOG_CRON
	case "authpriv":
		return gosyslog.LOG_AUTHPRIV
	case "ftp":
		return gosyslog.LOG_FTP
	case "local0":
		return gosyslog.LOG_LOCAL0
	case "local1":
		return gosyslog.LOG_LOCAL1
	case "local2":
		return gosyslog.LOG_LOCAL2
	case "local3":
		return gosyslog.LOG_LOCAL3
	case "local4":
		return gosyslog.LOG_LOCAL4
	case "local5":
		return gosyslog.LOG_LOCAL5
	case "local6":
		return gosyslog.LOG_LOCAL6
	case "local7":
		return gosyslog.LOG_LOCAL7
	}
	return gosyslog.LOG_AUTH
}
