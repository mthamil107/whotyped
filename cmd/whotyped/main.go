// Command whotyped tells server operators when an AI agent, rather than a
// human, is working on a Linux host over SSH.
//
// Subcommands: run, simulate, report, check, rules, version, help.
// Exit codes follow docs/design/ARCHITECTURE.md section 7 and docs/cli.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/whotyped/whotyped/internal/app"
	"github.com/whotyped/whotyped/internal/check"
	"github.com/whotyped/whotyped/internal/config"
	"github.com/whotyped/whotyped/internal/report"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/simulate"
	"github.com/whotyped/whotyped/internal/version"
)

const usageText = `whotyped - know when an AI agent, not a human, is on your server

usage: whotyped <command> [flags]

commands:
  run        start the daemon (or --replay / --once for offline runs)
  simulate   drive a benign agent-shaped session and wait for the alert
  report     summarise alerts.jsonl by account, server, agent or key
  check      inspect sshd, auditd, /proc and config; --fix installs drop-ins
  rules      validate or list rule packs
  version    print the build identity
  help       print this text (or: whotyped help <command>)

The config file is /etc/whotyped/config.yaml, or $WHOTYPED_CONFIG, or --config.
A missing file means built-in defaults. See docs/cli.md for exit codes.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest, stdout, stderr)
	case "simulate":
		return cmdSimulate(rest, stdout, stderr)
	case "report":
		return cmdReport(rest, stdout, stderr)
	case "check":
		return cmdCheck(rest, stdout, stderr)
	case "rules":
		return cmdRules(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return 0
	case simulate.AgentSubcommand:
		simulate.AgentMain()
		return 0
	case "help", "-h", "--help":
		if len(rest) > 0 {
			return run([]string{rest[0], "-h"}, stdout, stderr)
		}
		fmt.Fprint(stdout, usageText)
		return 0
	}
	fmt.Fprintf(stderr, "whotyped: unknown command %q\n\n%s", cmd, usageText)
	return 2
}

// defaultConfigPath honours $WHOTYPED_CONFIG over the compiled-in default.
func defaultConfigPath() string {
	if p := os.Getenv("WHOTYPED_CONFIG"); p != "" {
		return p
	}
	return config.DefaultPath
}

// newFlags builds a FlagSet whose -h prints a short usage and returns cleanly.
func newFlags(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("whotyped "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: whotyped %s %s\n\nflags:\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parse returns (ok, exit). -h yields ok=false, exit 0; a bad flag exit 2.
func parse(fs *flag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, 0
		}
		return false, 2
	}
	return true, 0
}

func loadConfig(path string, stderr io.Writer) (config.Config, bool) {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(stderr, "whotyped:", err)
		return cfg, false
	}
	return cfg, true
}

// ---------------------------------------------------------------------------
// run

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("run", "[--config file] [--once] [--dry-run] [--replay events.jsonl]", stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file")
	once := fs.Bool("once", false, "read the configured log files from the start, then exit")
	dry := fs.Bool("dry-run", false, "print alerts as JSON on stdout; no sinks, no state file")
	replay := fs.String("replay", "", "replay an events.jsonl through the pipeline instead of live readers")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	cfg, ok := loadConfig(*cfgPath, stderr)
	if !ok {
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "whotyped:", err)
		return 1
	}
	log := app.NewLogger(stderr, cfg.LogLevel)
	if !cfg.Loaded {
		log.Info("config file not found; built-in defaults in effect", "path", cfg.Path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := app.Run(ctx, cfg, app.Options{Once: *once, DryRun: *dry, Replay: *replay, Stdout: stdout, Logger: log})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, app.ErrNoReader):
		log.Error("no reader could start", "err", err)
		return 3
	default:
		log.Error("run failed", "err", err)
		return 1
	}
}

// ---------------------------------------------------------------------------
// simulate

func cmdSimulate(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("simulate", "[--offline] [--scenario name|list] [--target user@host] [--declared] [--timeout 120s] [--alerts path] [--json]", stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (for the default --alerts path)")
	offline := fs.Bool("offline", false, "replay the embedded scenario through the real pipeline; no ssh, any OS")
	scenario := fs.String("scenario", "claude-bash", "claude-bash | paramiko-mcp | local-agent | ansible | human | declared | vscode, or list")
	target := fs.String("target", "", "ssh destination; default localhost as the current user")
	declared := fs.Bool("declared", false, "send AI_AGENT=whotyped-simulate so the session is a declared agent")
	timeout := fs.Duration("timeout", 120*time.Second, "how long to wait for the alert")
	alerts := fs.String("alerts", "", "alerts.jsonl to poll; default from config (sinks.jsonfile.path)")
	socket := fs.String("socket", "", "reserved: daemon control socket (unused in v0.1)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if *offline || strings.EqualFold(*scenario, "list") {
		return simulate.RunOffline(*scenario, stdout, *jsonOut)
	}
	if *alerts == "" {
		if cfg, ok := loadConfig(*cfgPath, stderr); ok {
			*alerts = cfg.Sinks.JSONFile.Path
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return simulate.RunOnline(ctx, simulate.Options{
		Target: *target, Scenario: *scenario, Declared: *declared, Timeout: *timeout,
		AlertsPath: *alerts, Socket: *socket, JSON: *jsonOut, Stdout: stdout, Stderr: stderr,
	})
}

// ---------------------------------------------------------------------------
// report

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("report", "[--alerts path] [--since 7d] [--until RFC3339] [--by account|server|agent|key] [--format table|json|md] [--session id] [--min-level info]", stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (for the default --alerts path)")
	alerts := fs.String("alerts", "", "alerts.jsonl to read (rotated siblings included); default from config")
	since := fs.String("since", "", "window start: a duration back from now (7d, 36h) or an RFC3339 time; default everything")
	until := fs.String("until", "", "window end: RFC3339 time or a duration back from now; default now")
	by := fs.String("by", "account", "top-N dimension: account | server | agent | key")
	format := fs.String("format", "table", "table | json | md")
	session := fs.String("session", "", "print the alert timeline of one session id")
	minLevel := fs.String("min-level", "", "ignore alerts below this level: info | alert | high")
	top := fs.Int("top", 10, "rows in the top list")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if *alerts == "" {
		cfg, ok := loadConfig(*cfgPath, stderr)
		if !ok {
			return report.ExitError
		}
		*alerts = cfg.Sinks.JSONFile.Path
	}
	opts := report.Options{AlertsPath: *alerts, By: *by, Format: *format, Session: *session, MinLevel: *minLevel, Top: *top, Out: stdout}
	var err error
	if opts.Since, err = parseWhen(*since); err != nil {
		fmt.Fprintln(stderr, "whotyped report: --since:", err)
		return report.ExitError
	}
	if opts.Until, err = parseWhen(*until); err != nil {
		fmt.Fprintln(stderr, "whotyped report: --until:", err)
		return report.ExitError
	}
	code, err := report.Run(opts)
	if err != nil {
		fmt.Fprintln(stderr, "whotyped report:", err)
	}
	return code
}

// parseWhen accepts "" (zero), a duration back from now ("7d", "90m") or an
// RFC3339 / date value.
func parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := config.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is neither a duration (7d) nor an RFC3339 time", s)
}

// ---------------------------------------------------------------------------
// check

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("check", "[--config file] [--sshd-config file] [--fix] [--json] [--probe]", stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file")
	sshdConfig := fs.String("sshd-config", "", "sshd_config to inspect instead of /etc/ssh/sshd_config (works on any OS)")
	fix := fs.Bool("fix", false, "install the sshd drop-in and audit rules (Linux, root)")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	probe := fs.Bool("probe", false, "also run `sshd -T` for the effective settings (root)")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	opts := check.Options{ConfigPath: *cfgPath, Probe: *probe}
	if *sshdConfig != "" {
		data, err := os.ReadFile(*sshdConfig)
		if err != nil {
			fmt.Fprintln(stderr, "whotyped check:", err)
			return check.ExitCannotRun
		}
		opts.FS = &overlayFS{files: map[string][]byte{"etc/ssh/sshd_config": data}}
	}
	if *fix {
		results, code := check.Fix(opts, stdout)
		rep := check.Report{Results: results, Coverage: map[string]bool{}, ExitCode: code}
		if *jsonOut {
			_ = check.RenderJSON(rep, stdout)
		} else {
			for _, r := range results {
				fmt.Fprintf(stdout, "%-5s %s: %s\n", strings.ToUpper(r.Status), r.Name, r.Detail)
				if r.Fix != "" && r.Status != check.StatusPass {
					fmt.Fprintf(stdout, "      fix: %s\n", r.Fix)
				}
			}
		}
		return code
	}
	rep := check.Run(opts)
	if *jsonOut {
		if err := check.RenderJSON(rep, stdout); err != nil {
			fmt.Fprintln(stderr, "whotyped check:", err)
			return check.ExitCannotRun
		}
	} else {
		check.Render(rep, stdout)
	}
	return rep.ExitCode
}

// overlayFS serves a few in-memory files (the --sshd-config override) and
// falls back to the platform root for everything else, so the other probes
// keep working on Linux and report "skip" elsewhere.
type overlayFS struct {
	files map[string][]byte
}

func (o *overlayFS) Open(name string) (fs.File, error) {
	if data, ok := o.files[name]; ok {
		return &memFile{name: name, data: data}, nil
	}
	if base := platformRoot(); base != nil {
		return base.Open(name)
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

type memFile struct {
	name string
	data []byte
	off  int
}

func (m *memFile) Stat() (fs.FileInfo, error) { return memInfo{m}, nil }
func (m *memFile) Close() error               { return nil }
func (m *memFile) Read(p []byte) (int, error) {
	if m.off >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += n
	return n, nil
}

type memInfo struct{ f *memFile }

func (i memInfo) Name() string       { return i.f.name }
func (i memInfo) Size() int64        { return int64(len(i.f.data)) }
func (i memInfo) Mode() fs.FileMode  { return 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

// ---------------------------------------------------------------------------
// rules

func cmdRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: whotyped rules validate [dir...]\n       whotyped rules list [--config file]")
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "validate":
		return rulesValidate(args[1:], stdout, stderr)
	case "list":
		return rulesList(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "whotyped rules: unknown subcommand %q (want validate or list)\n", args[0])
	return 2
}

// rulesValidate loads the embedded packs plus the given directories, which
// is the pack the daemon would run with, and reports every problem.
func rulesValidate(dirs []string, stdout, stderr io.Writer) int {
	pack, err := rules.Load(dirs...)
	if err != nil {
		fmt.Fprintln(stderr, "whotyped rules validate:", err)
		return 1
	}
	errs := rules.Validate(pack)
	for _, e := range errs {
		fmt.Fprintln(stderr, "  -", e)
	}
	for _, w := range rules.Lint(pack) {
		fmt.Fprintln(stderr, "  - warning:", w)
	}
	src := "embedded defaults"
	if len(dirs) > 0 {
		src += " + " + strings.Join(dirs, ", ")
	}
	fmt.Fprintf(stdout, "pack %s (%s): %d agents, %d banners, %d styles, %d api hosts, %d profiles\n",
		pack.Version, src, len(pack.Agents), len(pack.Banners), len(pack.Styles), len(pack.APIHosts), len(pack.Profiles))
	if len(errs) > 0 {
		fmt.Fprintf(stdout, "invalid: %d problem(s)\n", len(errs))
		return 1
	}
	fmt.Fprintln(stdout, "valid")
	return 0
}

func rulesList(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("rules list", "[--config file]", stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (rules.dirs are merged)")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	var dirs []string
	if cfg, ok := loadConfig(*cfgPath, stderr); ok {
		dirs = cfg.Rules.Dirs
	}
	pack, err := rules.Load(dirs...)
	if err != nil {
		fmt.Fprintln(stderr, "whotyped rules list:", err)
		return 1
	}
	agents := append([]rules.Agent(nil), pack.Agents...)
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })
	fmt.Fprintf(stdout, "%-20s %-28s %-12s %5s %5s %5s %5s %5s\n", "ID", "DISPLAY", "VENDOR", "PROC", "ENV", "FLAGS", "HOSTS", "BANNR")
	for _, a := range agents {
		if a.Disabled {
			continue
		}
		fmt.Fprintf(stdout, "%-20s %-28s %-12s %5d %5d %5d %5d %5d\n", a.ID, trunc(a.Display, 28), trunc(a.Vendor, 12),
			len(a.ProcessNames), len(a.EnvVars)+len(a.EnvAIAgent), len(a.SkipFlags), len(a.APIHosts), len(a.SSHBanners))
	}
	fmt.Fprintf(stdout, "\npack %s: %d agents, %d banners, %d styles, %d api hosts, %d profiles\n",
		pack.Version, len(agents), len(pack.Banners), len(pack.Styles), len(pack.APIHosts), len(pack.Profiles))
	return 0
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
