// Package config loads and validates /etc/whotyped/config.yaml.
//
// The zero configuration is not usable; start from Default() and let Load
// overlay the file. Every duration accepts Go syntax plus a "d" suffix
// ("15m", "36h", "7d").
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whotyped/whotyped/internal/score"
)

// Config is the whole daemon configuration.
type Config struct {
	Host          string         `yaml:"host"`      // override for the alert "host" field; default os.Hostname
	StateDir      string         `yaml:"state_dir"` // state.json and default alerts.jsonl location
	LogLevel      string         `yaml:"log_level"` // debug | info | warn | error
	Readers       Readers        `yaml:"readers"`
	Rules         Rules          `yaml:"rules"`
	Scoring       Scoring        `yaml:"scoring"`
	Privacy       Privacy        `yaml:"privacy"`
	FreezeWindows []FreezeWindow `yaml:"freeze_windows"`
	Allowlist     Allowlist      `yaml:"allowlist"`
	Sinks         Sinks          `yaml:"sinks"`

	// Path is the file the config came from; Loaded is false when the file
	// was missing and defaults are in effect.
	Path   string `yaml:"-"`
	Loaded bool   `yaml:"-"`
}

// Readers configures the event sources.
type Readers struct {
	SSHLog  SSHLog  `yaml:"sshlog"`
	Auditd  Auditd  `yaml:"auditd"`
	Procfs  Procfs  `yaml:"procfs"`
	Netconn Netconn `yaml:"netconn"`
}

// SSHLog selects the sshd log source.
type SSHLog struct {
	Source string `yaml:"source"` // auto | journald | file
	File   string `yaml:"file"`   // for source=file, or the fallback for auto
}

// Auditd configures tailing of audit.log.
type Auditd struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

// Procfs configures the /proc scanner.
type Procfs struct {
	Enabled     bool     `yaml:"enabled"`
	Interval    Duration `yaml:"interval"`
	ReadEnviron bool     `yaml:"read_environ"`
}

// Netconn configures the /proc/net connection scanner.
type Netconn struct {
	Enabled  bool     `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	Resolve  bool     `yaml:"resolve"` // reverse-resolve destination IPs (network call)
}

// Rules configures rule pack overrides.
type Rules struct {
	Dirs       []string `yaml:"dirs"`
	AutoUpdate bool     `yaml:"auto_update"` // reserved; v0.1 never fetches packs
}

// Scoring configures the scorer.
type Scoring struct {
	Window               Duration         `yaml:"window"`
	Thresholds           score.Thresholds `yaml:"thresholds"`
	RealertInterval      Duration         `yaml:"realert_interval"`
	RequireTwoCategories bool             `yaml:"require_two_categories"`
}

// Privacy controls what reaches the alert evidence.
type Privacy struct {
	CommandText   string `yaml:"command_text"` // redacted | full | none
	HashUsernames bool   `yaml:"hash_usernames"`
}

// FreezeWindow is a period in which any agent activity is a violation. Give
// either a cron start plus a duration (recurring) or start/end (one-off).
type FreezeWindow struct {
	Name            string   `yaml:"name"`
	Cron            string   `yaml:"cron,omitempty"`     // 5-field: minute hour dom month dow
	Duration        Duration `yaml:"duration,omitempty"` // length of each cron occurrence
	Start           Time     `yaml:"start,omitempty"`    // RFC3339, one-off form
	End             Time     `yaml:"end,omitempty"`      // RFC3339, one-off form
	Timezone        string   `yaml:"timezone,omitempty"` // IANA name for cron evaluation; default local
	Level           string   `yaml:"level"`              // level for freeze_violation; default high
	IncludeDeclared bool     `yaml:"include_declared"`   // declared agents violate too; default true
}

// Allowlist selects which profiles apply on this host.
type Allowlist struct {
	ProfilesEnabled []string `yaml:"profiles_enabled"`
	ExtraFile       string   `yaml:"extra_file"` // an additional allowlist yaml outside rules.dirs
}

// Sinks configures alert outputs.
type Sinks struct {
	JSONFile   JSONFileSink   `yaml:"jsonfile"`
	Syslog     SyslogSink     `yaml:"syslog"`
	Webhook    WebhookSink    `yaml:"webhook"`
	Email      EmailSink      `yaml:"email"`
	Prometheus PrometheusSink `yaml:"prometheus"`
}

// JSONFileSink appends alerts to a rotated JSONL file.
type JSONFileSink struct {
	Enabled   bool   `yaml:"enabled"`
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
	Keep      int    `yaml:"keep"`
	MinLevel  string `yaml:"min_level"`
}

// SyslogSink writes to the local syslog.
type SyslogSink struct {
	Enabled  bool   `yaml:"enabled"`
	Tag      string `yaml:"tag"`
	Facility string `yaml:"facility"`
	MinLevel string `yaml:"min_level"`
}

// WebhookSink posts alerts to an HTTP endpoint.
type WebhookSink struct {
	Enabled  bool              `yaml:"enabled"`
	URL      string            `yaml:"url"`
	Format   string            `yaml:"format"` // json | slack | teams | discord
	MinLevel string            `yaml:"min_level"`
	Timeout  Duration          `yaml:"timeout"`
	Headers  map[string]string `yaml:"headers"`
}

// EmailSink sends alerts over SMTP. Credentials come from the environment
// variables named here, never from the file.
type EmailSink struct {
	Enabled     bool     `yaml:"enabled"`
	SMTP        string   `yaml:"smtp"` // host:port
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	StartTLS    bool     `yaml:"starttls"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	MinLevel    string   `yaml:"min_level"`
}

// PrometheusSink exposes counters on a local listener.
type PrometheusSink struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"` // host:port
}

// DefaultPath is where `whotyped run` looks when --config is not given.
const DefaultPath = "/etc/whotyped/config.yaml"

// Default returns the shipped defaults: all Linux readers on, JSON file
// sink on, everything that leaves the host off.
func Default() Config {
	host, _ := os.Hostname()
	return Config{
		Host:     host,
		StateDir: "/var/lib/whotyped",
		LogLevel: "info",
		Readers: Readers{
			SSHLog:  SSHLog{Source: "auto"},
			Auditd:  Auditd{Enabled: true, File: "/var/log/audit/audit.log"},
			Procfs:  Procfs{Enabled: true, Interval: Duration(2 * time.Second), ReadEnviron: true},
			Netconn: Netconn{Enabled: true, Interval: Duration(5 * time.Second), Resolve: false},
		},
		Rules: Rules{Dirs: []string{"/etc/whotyped/rules.d"}},
		Scoring: Scoring{
			Window:               Duration(15 * time.Minute),
			Thresholds:           score.DefaultThresholds,
			RealertInterval:      Duration(30 * time.Minute),
			RequireTwoCategories: true,
		},
		Privacy:   Privacy{CommandText: "redacted"},
		Allowlist: Allowlist{ProfilesEnabled: []string{}},
		Sinks: Sinks{
			JSONFile:   JSONFileSink{Enabled: true, Path: "/var/lib/whotyped/alerts.jsonl", MaxSizeMB: 50, Keep: 5, MinLevel: "info"},
			Syslog:     SyslogSink{Enabled: false, Tag: "whotyped", Facility: "auth", MinLevel: "alert"},
			Webhook:    WebhookSink{Enabled: false, Format: "json", MinLevel: "alert", Timeout: Duration(10 * time.Second)},
			Email:      EmailSink{Enabled: false, StartTLS: true, MinLevel: "high"},
			Prometheus: PrometheusSink{Enabled: false, Listen: "127.0.0.1:9477"},
		},
	}
}

// Load reads path over Default(). A missing file is not an error: the
// defaults are returned with Loaded=false so `check` can say so. Unknown
// keys are errors. Load does not call Validate; callers decide whether a
// validation failure is fatal (run) or a reported finding (check).
func Load(path string) (Config, error) {
	cfg := Default()
	cfg.Path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.decode(data); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	cfg.Loaded = true
	return cfg, nil
}

// Parse decodes YAML from r over Default(); used by tests and by tools
// that hold the file in memory.
func Parse(r io.Reader) (Config, error) {
	cfg := Default()
	data, err := io.ReadAll(r)
	if err != nil {
		return cfg, err
	}
	if err := cfg.decode(data); err != nil {
		return cfg, err
	}
	cfg.Loaded = true
	return cfg, nil
}

func (c *Config) decode(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	// Apply per-window defaults that a zero value cannot express.
	for i := range c.FreezeWindows {
		w := &c.FreezeWindows[i]
		if w.Level == "" {
			w.Level = "high"
		}
	}
	return nil
}

// UnmarshalYAML sets include_declared to true unless the file says otherwise.
func (w *FreezeWindow) UnmarshalYAML(n *yaml.Node) error {
	type raw FreezeWindow
	tmp := raw{IncludeDeclared: true}
	if err := n.Decode(&tmp); err != nil {
		return err
	}
	*w = FreezeWindow(tmp)
	return nil
}

var (
	levels       = map[string]bool{"info": true, "alert": true, "high": true}
	logLevels    = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	commandTexts = map[string]bool{"redacted": true, "full": true, "none": true}
	sshSources   = map[string]bool{"auto": true, "journald": true, "file": true}
	facilities   = map[string]bool{"auth": true, "authpriv": true, "daemon": true, "user": true, "syslog": true,
		"local0": true, "local1": true, "local2": true, "local3": true, "local4": true, "local5": true, "local6": true, "local7": true}
	formatRe = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

// Validate checks values, not the environment: it does not test whether
// paths exist or ports are free. It reports every problem it finds.
func (c Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if !logLevels[c.LogLevel] {
		add("log_level %q: want debug|info|warn|error", c.LogLevel)
	}
	if c.StateDir == "" {
		add("state_dir is required")
	}
	if !sshSources[c.Readers.SSHLog.Source] {
		add("readers.sshlog.source %q: want auto|journald|file", c.Readers.SSHLog.Source)
	}
	if c.Readers.SSHLog.Source == "file" && c.Readers.SSHLog.File == "" {
		add("readers.sshlog.file is required when source is file")
	}
	if c.Readers.Auditd.Enabled && c.Readers.Auditd.File == "" {
		add("readers.auditd.file is required when enabled")
	}
	if c.Readers.Procfs.Enabled && c.Readers.Procfs.Interval <= 0 {
		add("readers.procfs.interval must be positive")
	}
	if c.Readers.Netconn.Enabled && c.Readers.Netconn.Interval <= 0 {
		add("readers.netconn.interval must be positive")
	}

	if c.Scoring.Window <= 0 {
		add("scoring.window must be positive")
	}
	if c.Scoring.RealertInterval <= 0 {
		add("scoring.realert_interval must be positive")
	}
	th := c.Scoring.Thresholds
	if th.Info < 1 || th.High > 100 || !(th.Info < th.Alert && th.Alert < th.High) {
		add("scoring.thresholds must satisfy 1 <= info < alert < high <= 100 (got %d/%d/%d)", th.Info, th.Alert, th.High)
	}
	if !commandTexts[c.Privacy.CommandText] {
		add("privacy.command_text %q: want redacted|full|none", c.Privacy.CommandText)
	}

	names := map[string]bool{}
	for i, w := range c.FreezeWindows {
		where := fmt.Sprintf("freeze_windows[%d]", i)
		if w.Name == "" {
			add("%s: name is required", where)
		} else if names[w.Name] {
			add("%s: duplicate name %q", where, w.Name)
		}
		names[w.Name] = true
		hasCron := w.Cron != ""
		hasRange := !w.Start.IsZero() || !w.End.IsZero()
		switch {
		case hasCron && hasRange:
			add("%s: give cron+duration or start+end, not both", where)
		case hasCron:
			if _, err := ParseCron(w.Cron); err != nil {
				add("%s: cron: %v", where, err)
			}
			if w.Duration <= 0 {
				add("%s: duration is required with cron", where)
			}
		case hasRange:
			if w.Start.IsZero() || w.End.IsZero() {
				add("%s: both start and end are required", where)
			} else if !w.End.After(w.Start.Time) {
				add("%s: end must be after start", where)
			}
		default:
			add("%s: give cron+duration or start+end", where)
		}
		if w.Timezone != "" {
			if _, err := time.LoadLocation(w.Timezone); err != nil {
				add("%s: timezone: %v", where, err)
			}
		}
		if !levels[w.Level] {
			add("%s: level %q: want info|alert|high", where, w.Level)
		}
	}

	if s := c.Sinks.JSONFile; s.Enabled {
		if s.Path == "" {
			add("sinks.jsonfile.path is required")
		}
		if s.MaxSizeMB < 1 {
			add("sinks.jsonfile.max_size_mb must be >= 1")
		}
		if s.Keep < 0 {
			add("sinks.jsonfile.keep must be >= 0")
		}
		if !levels[s.MinLevel] {
			add("sinks.jsonfile.min_level %q: want info|alert|high", s.MinLevel)
		}
	}
	if s := c.Sinks.Syslog; s.Enabled {
		if s.Tag == "" {
			add("sinks.syslog.tag is required")
		}
		if !facilities[strings.ToLower(s.Facility)] {
			add("sinks.syslog.facility %q is not a syslog facility", s.Facility)
		}
		if !levels[s.MinLevel] {
			add("sinks.syslog.min_level %q: want info|alert|high", s.MinLevel)
		}
	}
	if s := c.Sinks.Webhook; s.Enabled {
		u, err := url.Parse(s.URL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			add("sinks.webhook.url must be an http(s) URL")
		}
		if !formatRe.MatchString(s.Format) {
			add("sinks.webhook.format %q: want a lowercase token such as json or slack", s.Format)
		}
		if !levels[s.MinLevel] {
			add("sinks.webhook.min_level %q: want info|alert|high", s.MinLevel)
		}
		if s.Timeout <= 0 {
			add("sinks.webhook.timeout must be positive")
		}
	}
	if s := c.Sinks.Email; s.Enabled {
		if _, _, err := net.SplitHostPort(s.SMTP); err != nil {
			add("sinks.email.smtp must be host:port")
		}
		if s.From == "" {
			add("sinks.email.from is required")
		}
		if len(s.To) == 0 {
			add("sinks.email.to must list at least one recipient")
		}
		if (s.UsernameEnv == "") != (s.PasswordEnv == "") {
			add("sinks.email.username_env and password_env must be set together")
		}
		if !levels[s.MinLevel] {
			add("sinks.email.min_level %q: want info|alert|high", s.MinLevel)
		}
	}
	if s := c.Sinks.Prometheus; s.Enabled {
		if _, port, err := net.SplitHostPort(s.Listen); err != nil {
			add("sinks.prometheus.listen must be host:port")
		} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			add("sinks.prometheus.listen port %q out of range", port)
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New("config: " + strings.Join(errs, "; "))
}

// ActiveFreeze returns the first freeze window covering now, or nil.
func (c Config) ActiveFreeze(now time.Time) *FreezeWindow {
	for i := range c.FreezeWindows {
		w := &c.FreezeWindows[i]
		if w.Active(now) {
			return w
		}
	}
	return nil
}

// Active reports whether now falls inside the window. For cron windows the
// most recent matching minute at or before now starts the occurrence; the
// window is [start, start+duration).
func (w *FreezeWindow) Active(now time.Time) bool {
	if w.Cron == "" {
		if w.Start.IsZero() || w.End.IsZero() {
			return false
		}
		return !now.Before(w.Start.Time) && now.Before(w.End.Time)
	}
	sched, err := ParseCron(w.Cron)
	if err != nil || w.Duration <= 0 {
		return false
	}
	loc := now.Location()
	if w.Timezone != "" {
		if l, err := time.LoadLocation(w.Timezone); err == nil {
			loc = l
		}
	}
	start, ok := sched.Prev(now.In(loc), time.Duration(w.Duration))
	if !ok {
		return false
	}
	return now.Before(start.Add(time.Duration(w.Duration)))
}

// ---------------------------------------------------------------------------
// Duration and Time YAML types

// Duration is a time.Duration that decodes from "15m", "36h", "7d" or a
// bare integer number of seconds.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// String formats like time.Duration but collapses whole days to "Nd".
func (d Duration) String() string {
	td := time.Duration(d)
	if td >= 24*time.Hour && td%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(td/(24*time.Hour)), 10) + "d"
	}
	return td.String()
}

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// ParseDuration accepts Go durations plus a trailing "d" (days) component
// ("7d", "1d12h") and bare integers as seconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	var days time.Duration
	if i := strings.IndexByte(s, 'd'); i > 0 {
		n, err := strconv.ParseFloat(s[:i], 64)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		days = time.Duration(n * float64(24*time.Hour))
		s = s[i+1:]
		if s == "" {
			return days, nil
		}
	}
	rest, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad duration: %w", err)
	}
	return days + rest, nil
}

// Time wraps time.Time so RFC3339 strings decode regardless of YAML tag.
type Time struct{ time.Time }

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *Time) UnmarshalYAML(n *yaml.Node) error {
	s := strings.TrimSpace(n.Value)
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if v, err := time.Parse(layout, s); err == nil {
			t.Time = v
			return nil
		}
	}
	return fmt.Errorf("bad time %q: want RFC3339 such as 2026-09-11T14:00:00Z", s)
}

// MarshalYAML implements yaml.Marshaler.
func (t Time) MarshalYAML() (any, error) {
	if t.IsZero() {
		return "", nil
	}
	return t.Format(time.RFC3339), nil
}
