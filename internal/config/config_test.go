package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Loaded {
		t.Error("Loaded should be false for a missing file")
	}
	if cfg.StateDir != "/var/lib/whotyped" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
host: web-03
readers:
  procfs:
    interval: 5s
  netconn:
    enabled: false
scoring:
  window: 20m
  realert_interval: 1h
  thresholds: {info: 30, alert: 60, high: 85}
freeze_windows:
  - name: weekend
    cron: "0 17 * * 5"
    duration: 63h
  - name: release
    start: 2026-09-20T00:00:00Z
    end: "2026-09-21T00:00:00Z"
    level: alert
    include_declared: false
allowlist:
  profiles_enabled: [ansible, vscode-remote]
sinks:
  webhook:
    enabled: true
    url: https://hooks.example.com/x
    headers: {Authorization: "Bearer from-env-not-here"}
  email:
    enabled: true
    smtp: smtp.example.com:587
    from: whotyped@example.com
    to: [secops@example.com]
    username_env: WHOTYPED_SMTP_USER
    password_env: WHOTYPED_SMTP_PASS
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Loaded || cfg.Path != path {
		t.Errorf("Loaded/Path not set: %v %q", cfg.Loaded, cfg.Path)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "web-03" {
		t.Errorf("host = %q", cfg.Host)
	}
	if cfg.Readers.Procfs.Interval.Duration() != 5*time.Second || !cfg.Readers.Procfs.ReadEnviron {
		t.Errorf("procfs partial overlay lost defaults: %+v", cfg.Readers.Procfs)
	}
	if cfg.Readers.Netconn.Enabled || cfg.Readers.Netconn.Interval.Duration() != 5*time.Second {
		t.Errorf("netconn: %+v", cfg.Readers.Netconn)
	}
	if cfg.Scoring.Window.Duration() != 20*time.Minute || cfg.Scoring.RealertInterval.Duration() != time.Hour {
		t.Errorf("scoring durations: %+v", cfg.Scoring)
	}
	if cfg.Scoring.Thresholds.Alert != 60 || !cfg.Scoring.RequireTwoCategories {
		t.Errorf("scoring: %+v", cfg.Scoring)
	}
	if len(cfg.FreezeWindows) != 2 {
		t.Fatalf("freeze windows: %+v", cfg.FreezeWindows)
	}
	if w := cfg.FreezeWindows[0]; w.Level != "high" || !w.IncludeDeclared || w.Duration.Duration() != 63*time.Hour {
		t.Errorf("cron window defaults: %+v", w)
	}
	if w := cfg.FreezeWindows[1]; w.Level != "alert" || w.IncludeDeclared || w.Start.IsZero() || w.End.IsZero() {
		t.Errorf("one-off window: %+v", w)
	}
	if !cfg.Sinks.JSONFile.Enabled || cfg.Sinks.JSONFile.MaxSizeMB != 50 {
		t.Errorf("jsonfile defaults lost: %+v", cfg.Sinks.JSONFile)
	}
	if cfg.Sinks.Webhook.Format != "json" || cfg.Sinks.Webhook.Timeout.Duration() != 10*time.Second || cfg.Sinks.Webhook.Headers["Authorization"] == "" {
		t.Errorf("webhook: %+v", cfg.Sinks.Webhook)
	}
	if !cfg.Sinks.Email.StartTLS {
		t.Errorf("email starttls default lost: %+v", cfg.Sinks.Email)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	_, err := Parse(strings.NewReader("scorring:\n  window: 1m\n"))
	if err == nil || !strings.Contains(err.Error(), "scorring") {
		t.Errorf("unknown key not reported: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"thresholds", "scoring:\n  thresholds: {info: 70, alert: 40, high: 90}\n", "scoring.thresholds"},
		{"threshold high", "scoring:\n  thresholds: {info: 40, alert: 70, high: 101}\n", "scoring.thresholds"},
		{"min_level", "sinks:\n  jsonfile:\n    min_level: loud\n", "sinks.jsonfile.min_level"},
		{"webhook scheme", "sinks:\n  webhook:\n    enabled: true\n    url: ftp://x/y\n", "sinks.webhook.url"},
		{"webhook no host", "sinks:\n  webhook:\n    enabled: true\n    url: https://\n", "sinks.webhook.url"},
		{"command_text", "privacy:\n  command_text: verbose\n", "privacy.command_text"},
		{"webhook format", "sinks:\n  webhook:\n    enabled: true\n    url: https://h/x\n    format: pagerduty\n", "sinks.webhook.format"},
		{"hash salt", "host: ''\nprivacy:\n  hash_usernames: true\n  hash_salt: ''\n", "privacy.hash_salt"},
		{"sshlog source", "readers:\n  sshlog:\n    source: magic\n", "readers.sshlog.source"},
		{"sshlog file", "readers:\n  sshlog:\n    source: file\n", "readers.sshlog.file"},
		{"cron", "freeze_windows:\n  - name: x\n    cron: 'bad'\n    duration: 1h\n", "cron"},
		{"cron no duration", "freeze_windows:\n  - name: x\n    cron: '0 17 * * 5'\n", "duration is required"},
		{"both forms", "freeze_windows:\n  - name: x\n    cron: '0 17 * * 5'\n    duration: 1h\n    start: 2026-09-20T00:00:00Z\n    end: 2026-09-21T00:00:00Z\n", "not both"},
		{"reversed", "freeze_windows:\n  - name: x\n    start: 2026-09-22T00:00:00Z\n    end: 2026-09-21T00:00:00Z\n", "end must be after start"},
		{"window level", "freeze_windows:\n  - name: x\n    cron: '0 17 * * 5'\n    duration: 1h\n    level: loud\n", "level"},
		{"duplicate name", "freeze_windows:\n  - name: x\n    cron: '0 17 * * 5'\n    duration: 1h\n  - name: x\n    cron: '0 17 * * 5'\n    duration: 1h\n", "duplicate name"},
		{"email", "sinks:\n  email:\n    enabled: true\n    smtp: smtp.example.com\n", "sinks.email.smtp"},
		{"prom", "sinks:\n  prometheus:\n    enabled: true\n    listen: ':99999'\n", "sinks.prometheus.listen"},
		{"log level", "log_level: chatty\n", "log_level"},
		{"state dir", "state_dir: ''\n", "state_dir"},
	}
	for _, c := range cases {
		cfg, err := Parse(strings.NewReader(c.yaml))
		if err != nil {
			t.Errorf("%s: parse: %v", c.name, err)
			continue
		}
		err = cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Validate = %v, want mention of %q", c.name, err, c.want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"15m":   15 * time.Minute,
		"36h":   36 * time.Hour,
		"7d":    7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour,
		"0.5d":  12 * time.Hour,
		"90":    90 * time.Second,
		"250ms": 250 * time.Millisecond,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "d", "7dd", "1x", "abc"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
	if s := Duration(7 * 24 * time.Hour).String(); s != "7d" {
		t.Errorf("String = %q", s)
	}
	if s := Duration(90 * time.Minute).String(); s != "1h30m0s" {
		t.Errorf("String = %q", s)
	}
}

func TestBadDurationInFile(t *testing.T) {
	_, err := Parse(strings.NewReader("scoring:\n  window: fortnight\n"))
	if err == nil {
		t.Error("bad duration accepted")
	}
	_, err = Parse(strings.NewReader("freeze_windows:\n  - name: x\n    start: 'next tuesday'\n    end: 2026-09-21T00:00:00Z\n"))
	if err == nil {
		t.Error("bad time accepted")
	}
}

// TestExampleConfigLoads keeps deploy/config.example.yaml honest: it must
// decode with no unknown keys and validate.
func TestExampleConfigLoads(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Loaded {
		t.Fatal("example config not found at", path)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.FreezeWindows) == 0 {
		t.Error("example should demonstrate a freeze window")
	}
}

func TestWebhookFormatsAndHashSalt(t *testing.T) {
	for _, f := range []string{"json", "slack", "teams", "discord", "generic"} {
		cfg, err := Parse(strings.NewReader("sinks:\n  webhook:\n    enabled: true\n    url: https://h/x\n    format: " + f + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("format %s rejected: %v", f, err)
		}
	}
	cfg := Default()
	if cfg.Privacy.HashSalt == "" || cfg.Privacy.HashSalt != cfg.Host {
		t.Errorf("hash_salt should default to the host name, got %q (host %q)", cfg.Privacy.HashSalt, cfg.Host)
	}
	cfg, err := Parse(strings.NewReader("privacy:\n  hash_usernames: true\n  hash_salt: pepper\n"))
	if err != nil || !cfg.Privacy.HashUsernames || cfg.Privacy.HashSalt != "pepper" {
		t.Fatalf("privacy parse: %+v %v", cfg.Privacy, err)
	}
}
