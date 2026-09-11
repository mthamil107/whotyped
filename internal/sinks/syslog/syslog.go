// Package syslog delivers alerts to the local syslog daemon (Linux only).
//
// Each alert is one message whose body is the alert JSON; the syslog tag
// (default "whotyped") is prepended by the daemon, so a line reads
// "whotyped[pid]: {json}". Severity follows the alert level: info -> LOG_INFO,
// alert -> LOG_WARNING, high -> LOG_ALERT.
package syslog

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultTag and DefaultFacility are used when the caller passes "".
const (
	DefaultTag      = "whotyped"
	DefaultFacility = "auth"
)

// ErrUnsupported is returned by New on platforms without log/syslog.
var ErrUnsupported = errors.New("syslog sink not supported on this platform")

// Facilities lists the accepted facility names, for config validation.
var Facilities = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// ValidFacility reports whether name is a known facility ("" counts as the default).
func ValidFacility(name string) bool {
	if name == "" {
		return true
	}
	name = strings.ToLower(name)
	for _, f := range Facilities {
		if f == name {
			return true
		}
	}
	return false
}

func normalise(tag, facility string) (string, string, error) {
	if tag == "" {
		tag = DefaultTag
	}
	if facility == "" {
		facility = DefaultFacility
	}
	facility = strings.ToLower(facility)
	if !ValidFacility(facility) {
		return "", "", fmt.Errorf("syslog: unknown facility %q", facility)
	}
	return tag, facility, nil
}
