// Package app wires readers, correlator, scorer, dispatcher, sinks, metrics
// and state into the `whotyped run` pipeline (ARCHITECTURE.md section 4):
//
//	readers -> chan event.Event (4096, drop-oldest) -> correlator goroutine
//	  -> Scorer.Evaluate (immediate on strong events, else every 2 s)
//	  -> Dispatcher.Observe -> sinks
//	ticker 30 s: Expire -> Dispatcher.Ended, state snapshot
//
// The same loop serves three modes. Live: Linux readers tail the system.
// Replay: an events.jsonl drives the pipeline and its clock, on any OS.
// Once: the configured log files are read from the start and the process
// exits when they are consumed.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mthamil107/whotyped/internal/alert"
	"github.com/mthamil107/whotyped/internal/config"
	"github.com/mthamil107/whotyped/internal/event"
	"github.com/mthamil107/whotyped/internal/metrics"
	"github.com/mthamil107/whotyped/internal/readers"
	"github.com/mthamil107/whotyped/internal/readers/auditd"
	"github.com/mthamil107/whotyped/internal/readers/procfs"
	"github.com/mthamil107/whotyped/internal/readers/sshlog"
	"github.com/mthamil107/whotyped/internal/rules"
	"github.com/mthamil107/whotyped/internal/score"
	"github.com/mthamil107/whotyped/internal/session"
	"github.com/mthamil107/whotyped/internal/sinks/email"
	"github.com/mthamil107/whotyped/internal/sinks/jsonfile"
	"github.com/mthamil107/whotyped/internal/sinks/syslog"
	"github.com/mthamil107/whotyped/internal/sinks/webhook"
	"github.com/mthamil107/whotyped/internal/state"
	"github.com/mthamil107/whotyped/internal/version"
)

// Sentinel errors that main maps to exit codes (ARCHITECTURE.md section 7).
var (
	// ErrConfig wraps configuration and rule-pack problems (exit 1).
	ErrConfig = errors.New("configuration error")
	// ErrNoReader means no event source could start on this host (exit 3).
	ErrNoReader = errors.New("no event reader could start")
)

// Options selects the run mode.
type Options struct {
	Once   bool      // read the configured files from the start, then exit
	DryRun bool      // print alerts as JSON to Stdout; register no sinks, touch no state
	Replay string    // path to an events.jsonl replayed instead of readers (any OS)
	Stdout io.Writer // default os.Stdout
	Logger *slog.Logger
}

const (
	queueSize    = 4096
	evalInterval = 2 * time.Second
	tickInterval = 30 * time.Second
	stateFile    = "state.json"
	cursorFile   = "journal.cursor"
)

// Run builds the pipeline for cfg and blocks until ctx is cancelled (live
// mode) or the input is consumed (replay / once).
func Run(ctx context.Context, cfg config.Config, opts Options) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	log := opts.Logger
	if log == nil {
		log = NewLogger(os.Stderr, cfg.LogLevel)
	}
	slog.SetDefault(log)

	pack, err := loadPack(cfg, log)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}

	p := newPipeline(cfg, opts, pack, log)
	defer p.disp.Close()

	if !opts.DryRun && cfg.Sinks.Prometheus.Enabled {
		go func() {
			if err := p.reg.Serve(ctx, cfg.Sinks.Prometheus.Listen); err != nil {
				log.Error("metrics listener stopped", "err", err)
			}
		}()
	}
	p.registerSinks()
	defer p.closeSinks()
	p.disp.Start(ctx)

	switch {
	case opts.Replay != "":
		return p.runReplay(opts.Replay)
	case opts.Once:
		return p.runOnce()
	default:
		return p.runLive(ctx)
	}
}

// NewLogger returns the daemon's slog logger: text to w at the configured level.
func NewLogger(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lv}))
}

// loadPack merges the embedded packs, cfg.Rules.Dirs and allowlist.extra_file,
// validates the result and keeps only the profiles enabled for this host.
func loadPack(cfg config.Config, log *slog.Logger) (*rules.Pack, error) {
	pack, err := rules.Load(cfg.Rules.Dirs...)
	if err != nil {
		return nil, err
	}
	if extra := cfg.Allowlist.ExtraFile; extra != "" {
		data, err := os.ReadFile(extra)
		if err != nil {
			return nil, fmt.Errorf("allowlist.extra_file: %w", err)
		}
		f, err := rules.ParseFile(extra, data)
		if err != nil {
			return nil, err
		}
		rules.Merge(pack, f)
	}
	if errs := rules.Validate(pack); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return nil, errors.New("rules: " + strings.Join(msgs, "; "))
	}
	// Profiles are opt-in per host: the scorer applies every profile in the
	// pack, so the ones not listed in allowlist.profiles_enabled are dropped
	// here. Anything else would let a shipped profile allowlist everyone.
	enabled := map[string]bool{}
	for _, id := range cfg.Allowlist.ProfilesEnabled {
		enabled[id] = true
		if pack.ProfileByID(id) == nil {
			log.Warn("allowlist.profiles_enabled names an unknown profile", "profile", id)
		}
	}
	kept := pack.Profiles[:0]
	for _, pr := range pack.Profiles {
		if enabled[pr.ID] {
			kept = append(kept, pr)
		}
	}
	pack.Profiles = kept
	log.Info("rules loaded", "version", pack.Version, "agents", len(pack.Agents), "banners", len(pack.Banners),
		"styles", len(pack.Styles), "api_hosts", len(pack.APIHosts), "profiles_enabled", len(pack.Profiles))
	return pack, nil
}

// ---------------------------------------------------------------------------
// clock

// clock is time.Now in live mode and the last event timestamp in replay and
// once modes, so windows, rate limits and freeze checks follow the data.
type clock struct {
	mu     sync.Mutex
	driven bool
	t      time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.driven && !c.t.IsZero() {
		return c.t
	}
	return time.Now()
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	if t.After(c.t) {
		c.t = t
	}
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// pipeline

type pipeline struct {
	cfg  config.Config
	opts Options
	log  *slog.Logger
	pack *rules.Pack

	clk    *clock
	corr   *session.Correlator
	scorer *score.Scorer
	disp   *alert.Dispatcher
	reg    *metrics.Registry
	std    *metrics.Standard

	dirty     map[string]*session.Track // tracks changed since their last evaluation
	lastFlush time.Time
	lastTick  time.Time

	audit   *auditd.Reader // for Position() in the state snapshot; nil when disabled
	closers []func()
	dropped atomic.Int64 // incremented by the forwarder goroutine, read by the main loop

	persist   bool // state.json is read and written
	statePath string
}

func newPipeline(cfg config.Config, opts Options, pack *rules.Pack, log *slog.Logger) *pipeline {
	p := &pipeline{
		cfg:   cfg,
		opts:  opts,
		log:   log,
		pack:  pack,
		clk:   &clock{driven: opts.Replay != "" || opts.Once},
		dirty: map[string]*session.Track{},
		reg:   metrics.NewRegistry(),
	}
	p.std = metrics.NewStandard(p.reg, version.Version, version.Commit)
	p.persist = opts.Replay == "" && !opts.DryRun
	p.statePath = filepath.Join(cfg.StateDir, stateFile)

	window := cfg.Scoring.Window.Duration()
	p.corr = session.New(session.Options{Window: window, Now: p.clk.Now, OnDrop: p.forget})
	sc := score.DefaultConfig()
	sc.Thresholds = cfg.Scoring.Thresholds
	sc.RequireTwoCategories = cfg.Scoring.RequireTwoCategories
	sc.Window = window
	sc.CommandText = cfg.Privacy.CommandText
	p.scorer = score.New(sc)
	p.disp = alert.New(alert.Options{
		Host:            cfg.Host,
		RealertInterval: cfg.Scoring.RealertInterval.Duration(),
		Window:          window,
		Thresholds:      cfg.Scoring.Thresholds,
		Now:             p.clk.Now,
		Logger:          log,
		HashUsernames:   cfg.Privacy.HashUsernames,
		HashSalt:        cfg.Privacy.HashSalt,
	})
	return p
}

// ---------------------------------------------------------------------------
// state

// restore loads state.json and returns the audit resume position.
func (p *pipeline) restore() (offset int64, inode uint64) {
	if !p.persist {
		return 0, 0
	}
	st, err := state.Load(p.statePath)
	if err != nil {
		p.log.Warn("state not restored", "err", err)
		return 0, 0
	}
	if len(st.Tracks) > 0 || len(st.Dedupe) > 0 {
		p.corr.Restore(st.Tracks)
		p.disp.Restore(st.Dedupe)
		p.log.Info("state restored", "tracks", len(st.Tracks), "dedupe_keys", len(st.Dedupe), "saved_at", st.SavedAt)
	}
	return st.AuditOffset, st.AuditInode
}

func (p *pipeline) saveState() {
	if !p.persist {
		return
	}
	st := state.State{
		Tracks:  p.corr.Snapshot(),
		Dedupe:  p.disp.Dedupe(),
		SavedAt: time.Now(),
	}
	if p.audit != nil {
		st.AuditOffset, st.AuditInode = p.audit.Position()
	}
	// The journal source owns its cursor file; mirror it for operators
	// reading state.json.
	if b, err := os.ReadFile(filepath.Join(p.cfg.StateDir, cursorFile)); err == nil {
		st.JournalCursor = strings.TrimSpace(string(b))
	}
	if err := state.Save(p.statePath, st); err != nil {
		p.log.Warn("state save failed", "err", err)
	}
}

// ---------------------------------------------------------------------------
// sinks

// stdoutSink prints every alert as one JSON line (--dry-run).
type stdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *stdoutSink) Name() string { return "stdout" }

func (s *stdoutSink) Send(_ context.Context, a alert.Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}

func (p *pipeline) registerSinks() {
	if p.opts.DryRun {
		p.disp.Register(&stdoutSink{w: p.opts.Stdout}, score.LevelInfo, 1024)
		return
	}
	s := p.cfg.Sinks
	if s.JSONFile.Enabled {
		jf, err := jsonfile.New(jsonfile.Options{Path: s.JSONFile.Path, MaxSizeMB: s.JSONFile.MaxSizeMB, Keep: s.JSONFile.Keep})
		if err != nil {
			p.log.Error("jsonfile sink disabled", "err", err)
		} else {
			p.disp.Register(jf, score.ParseLevel(s.JSONFile.MinLevel), 256)
			p.closers = append(p.closers, func() { _ = jf.Close() })
		}
	}
	if s.Syslog.Enabled {
		sl, err := syslog.New(s.Syslog.Tag, s.Syslog.Facility)
		if err != nil {
			p.log.Warn("syslog sink disabled", "err", err)
		} else {
			p.disp.Register(sl, score.ParseLevel(s.Syslog.MinLevel), 256)
			if c, ok := sl.(io.Closer); ok {
				p.closers = append(p.closers, func() { _ = c.Close() })
			}
		}
	}
	if s.Webhook.Enabled {
		// "json" is the config alias of the generic format; webhook.New maps it.
		p.disp.Register(webhook.New(s.Webhook.URL, s.Webhook.Format, s.Webhook.Timeout.Duration(), s.Webhook.Headers),
			score.ParseLevel(s.Webhook.MinLevel), 256)
	}
	if s.Email.Enabled {
		host, portStr, err := net.SplitHostPort(s.Email.SMTP)
		port, _ := strconv.Atoi(portStr)
		var em *email.Sink
		if err == nil {
			em, err = email.New(email.Options{
				Host: host, Port: port, From: s.Email.From, To: s.Email.To,
				UsernameEnv: s.Email.UsernameEnv, PasswordEnv: s.Email.PasswordEnv,
				DisableStartTLS: !s.Email.StartTLS,
			})
		}
		if err != nil {
			p.log.Error("email sink disabled", "err", err)
		} else {
			p.disp.Register(em, score.ParseLevel(s.Email.MinLevel), 64)
		}
	}
}

func (p *pipeline) closeSinks() {
	for _, c := range p.closers {
		c()
	}
}

// ---------------------------------------------------------------------------
// core loop pieces (all called from the correlator goroutine)

func (p *pipeline) handle(ev event.Event) {
	if !ev.TS.IsZero() {
		p.clk.Set(ev.TS)
	}
	now := p.clk.Now()
	p.std.EventsTotal.Inc(string(ev.Kind))
	if ev.Source != "" {
		p.std.LastEventTimestamp.Set(float64(now.Unix()), ev.Source)
	}
	t, strong := p.corr.Apply(ev)
	if t == nil {
		return
	}
	if strong || now.Sub(t.LastEval) >= evalInterval {
		p.evaluate(t, now)
	} else {
		p.dirty[t.ID] = t
	}
}

func (p *pipeline) evaluate(t *session.Track, now time.Time) {
	delete(p.dirty, t.ID)
	v := p.scorer.Evaluate(t, p.pack, now)
	t.LastEval = now
	for _, a := range p.disp.Observe(t, v, p.freezeFor(now, v)) {
		p.std.AlertsTotal.Inc(string(a.Level), string(a.Class))
		p.log.Info("alert", "event", a.Event, "class", a.Class, "level", a.Level, "score", a.Score,
			"user", a.User, "src_ip", a.SrcIP, "agent", a.Agent, "session", a.SessionID)
	}
}

// flushDirty evaluates rate-limited tracks whose 2 s grace has passed (all
// of them when force is set, e.g. at the end of a replay).
func (p *pipeline) flushDirty(now time.Time, force bool) {
	p.lastFlush = now
	ids := make([]string, 0, len(p.dirty))
	for id := range p.dirty {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := p.dirty[id]
		if force || now.Sub(t.LastEval) >= evalInterval {
			p.evaluate(t, now)
		}
	}
}

// maintain is the 30 s tick: expire tracks, emit agent_ended, refresh gauges.
func (p *pipeline) maintain(now time.Time) {
	p.lastTick = now
	for _, t := range p.corr.Expire(now) {
		delete(p.dirty, t.ID)
		if a := p.disp.Ended(t); a != nil {
			p.std.AlertsTotal.Inc(string(a.Level), string(a.Class))
			p.log.Info("alert", "event", a.Event, "user", a.User, "session", a.SessionID, "max_level", a.Level)
		}
	}
	p.std.TracksOpen.Set(float64(len(p.corr.Tracks())))
	stats := map[string]metrics.SinkStats{}
	for name, st := range p.disp.Stats() {
		stats[name] = metrics.SinkStats{Sent: st.Sent, Failed: st.Failed, Dropped: st.Dropped}
	}
	p.std.SetSinkStats(stats)
}

// forget is the correlator's OnDrop hook: a track that vanished without
// ending (a provisional track absorbed into its keyed one) must not linger
// in the dirty set, where flushDirty would score and alert on it, nor keep
// its dedupe memo in the dispatcher.
func (p *pipeline) forget(id string) {
	delete(p.dirty, id)
	p.disp.Forget(id)
}

// freezeFor maps the active config freeze window (if any) to the alert form,
// carrying the window's configured violation level.
func (p *pipeline) freezeFor(now time.Time, v score.Verdict) *alert.Freeze {
	w := p.cfg.ActiveFreeze(now)
	if w == nil {
		return nil
	}
	if v.Class == score.ClassDeclared && !w.IncludeDeclared {
		return nil
	}
	return &alert.Freeze{Name: w.Name, Until: freezeUntil(w, now), Level: score.ParseLevel(w.Level)}
}

// freezeUntil computes the end of the occurrence covering now.
func freezeUntil(w *config.FreezeWindow, now time.Time) time.Time {
	if w.Cron == "" {
		return w.End.Time
	}
	sched, err := config.ParseCron(w.Cron)
	if err != nil {
		return now
	}
	loc := now.Location()
	if w.Timezone != "" {
		if l, err := time.LoadLocation(w.Timezone); err == nil {
			loc = l
		}
	}
	d := w.Duration.Duration()
	if start, ok := sched.Prev(now.In(loc), d); ok {
		return start.Add(d)
	}
	return now
}

// feed pushes a finite, time-ordered event list through the loop, running
// the flush and maintenance steps whenever the data clock crosses them.
func (p *pipeline) feed(events []event.Event) {
	for _, ev := range events {
		p.handle(ev)
		now := p.clk.Now()
		if p.lastFlush.IsZero() || now.Sub(p.lastFlush) >= evalInterval {
			p.flushDirty(now, false)
		}
		if p.lastTick.IsZero() {
			p.lastTick = now
		} else if now.Sub(p.lastTick) >= tickInterval {
			p.maintain(now)
		}
	}
	p.flushDirty(p.clk.Now(), true)
}

// ---------------------------------------------------------------------------
// replay and once

func (p *pipeline) runReplay(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	defer f.Close()
	events, skipped, err := score.ReadEventsSkipped(f)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	if skipped > 0 {
		p.log.Warn("replay: events without a timestamp skipped", "skipped", skipped)
	}
	p.log.Info("replaying events", "file", path, "events", len(events))
	p.feed(events)
	// Alerts show the score at the moment a level was crossed; log where
	// each track ended up so a replay is comparable with simulate --offline.
	now := p.clk.Now()
	for _, t := range p.corr.Tracks() {
		v := p.scorer.Evaluate(t, p.pack, now)
		p.log.Info("replay final verdict", "session", t.ID, "user", t.Key.User, "src_ip", t.Key.SrcIP,
			"score", v.Score, "class", v.Class, "level", v.Level, "mode", v.Mode, "agent", v.Agent)
	}
	p.log.Info("replay done", "tracks", len(p.corr.Tracks()))
	return nil
}

// runOnce reads the configured sources from the start (sshd log file,
// audit.log, one /proc scan) and processes them as a replay. journald is
// not consulted; export it with `journalctl -o json > file` and point
// readers.sshlog.file at it.
func (p *pipeline) runOnce() error {
	var events []event.Event
	sources := 0
	r := p.cfg.Readers

	if r.SSHLog.Source != "journald" {
		candidates := []string{r.SSHLog.File}
		if r.SSHLog.File == "" {
			candidates = []string{"/var/log/auth.log", "/var/log/secure"}
		}
		for _, c := range candidates {
			f, err := os.Open(c)
			if err != nil {
				continue
			}
			evs := sshlog.ReplayReader(f, time.Now())
			f.Close()
			p.log.Info("once: read sshd log", "file", c, "events", len(evs))
			events = append(events, evs...)
			sources++
			break
		}
	}
	if r.Auditd.Enabled {
		if f, err := os.Open(r.Auditd.File); err == nil {
			evs := auditd.Replay(f)
			f.Close()
			p.log.Info("once: read audit log", "file", r.Auditd.File, "events", len(evs))
			events = append(events, evs...)
			sources++
		} else {
			p.log.Warn("once: audit log not readable", "file", r.Auditd.File, "err", err)
		}
	}
	if r.Procfs.Enabled && runtime.GOOS == "linux" {
		if _, err := os.Stat("/proc/self"); err == nil {
			sc := &procfs.Scanner{
				FS:          os.DirFS("/proc"),
				Readlink:    func(name string) (string, error) { return os.Readlink(filepath.Join("/proc", name)) },
				Pack:        p.pack,
				ReadEnviron: r.Procfs.ReadEnviron,
				UserLookup:  procfs.NewPasswdLookup(func() (fs.File, error) { return os.Open("/etc/passwd") }),
			}
			evs, _ := sc.Scan(nil)
			if r.Netconn.Enabled {
				nevs, _ := sc.ScanNet(nil)
				evs = append(evs, nevs...)
			}
			p.log.Info("once: scanned /proc", "events", len(evs))
			events = append(events, evs...)
			sources++
		}
	}
	if sources == 0 {
		return fmt.Errorf("%w: nothing readable among the configured sources", ErrNoReader)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	p.feed(events)
	p.log.Info("once: done", "events", len(events), "tracks", len(p.corr.Tracks()))
	return nil
}

// ---------------------------------------------------------------------------
// live

type readerResult struct {
	name string
	err  error
}

func (p *pipeline) buildReaders(auditOffset int64, auditInode uint64) []readers.Reader {
	r := p.cfg.Readers
	var list []readers.Reader

	source := r.SSHLog.Source
	if source == "journald" {
		source = "journal" // config vocabulary vs reader vocabulary
	}
	list = append(list, sshlog.New(sshlog.Options{
		Source:     source,
		File:       r.SSHLog.File,
		CursorFile: filepath.Join(p.cfg.StateDir, cursorFile),
		Now:        p.clk.Now,
		Logf:       func(format string, args ...any) { p.log.Debug(fmt.Sprintf(format, args...)) },
	}))
	if r.Auditd.Enabled {
		p.audit = auditd.New(auditd.Options{
			Source:       "auto",
			File:         r.Auditd.File,
			ResumeOffset: auditOffset,
			ResumeInode:  auditInode,
			Now:          p.clk.Now,
		})
		list = append(list, p.audit)
	}
	if r.Procfs.Enabled {
		po := procfs.Options{
			Interval:    r.Procfs.Interval.Duration(),
			NetInterval: r.Netconn.Interval.Duration(),
			NoEnviron:   !r.Procfs.ReadEnviron,
			NoNet:       !r.Netconn.Enabled, // readers.netconn.enabled: false disables ScanNet and DNS
		}
		if r.Netconn.Resolve == config.ResolveNone {
			// readers.netconn.resolve: none -> never perform DNS; only
			// literal-IP and CIDR api_hosts rules can match.
			po.Resolver = procfs.MapResolver{}
		}
		list = append(list, procfs.New(p.pack, po))
	}
	return list
}

func (p *pipeline) runLive(ctx context.Context) error {
	auditOffset, auditInode := p.restore()
	rs := p.buildReaders(auditOffset, auditInode)

	rctx, stopReaders := context.WithCancel(ctx)
	defer stopReaders()

	in := make(chan event.Event, 256)
	queue := make(chan event.Event, queueSize)
	results := make(chan readerResult, len(rs))
	var wg sync.WaitGroup

	for _, r := range rs {
		wg.Add(1)
		p.std.ReaderUp.Set(1, r.Name())
		go func(r readers.Reader) {
			defer wg.Done()
			results <- readerResult{r.Name(), r.Run(rctx, in)}
		}(r)
	}
	// Forwarder: readers block on `in`; `queue` is drop-oldest so a stalled
	// correlator sheds the stalest observations rather than the newest.
	go func() {
		for {
			select {
			case <-rctx.Done():
				return
			case ev := <-in:
				select {
				case queue <- ev:
					continue
				default:
				}
				select {
				case <-queue:
					p.dropped.Add(1)
					p.std.EventsDroppedTotal.Inc()
				default:
				}
				select {
				case queue <- ev:
				default:
					p.dropped.Add(1)
					p.std.EventsDroppedTotal.Inc()
				}
			}
		}
	}()

	p.log.Info("whotyped running", "version", version.Version, "host", p.cfg.Host, "readers", len(rs), "os", runtime.GOOS)

	running, failed := len(rs), 0
	flush := time.NewTicker(evalInterval)
	defer flush.Stop()
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()
	p.lastTick = p.clk.Now()

	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case ev := <-queue:
			p.handle(ev)
		case <-flush.C:
			p.flushDirty(p.clk.Now(), false)
		case <-tick.C:
			p.maintain(p.clk.Now())
			p.saveState()
		case res := <-results:
			running--
			p.std.ReaderUp.Set(0, res.name)
			switch {
			case res.err == nil || errors.Is(res.err, context.Canceled):
				p.log.Info("reader stopped", "reader", res.name)
			case errors.Is(res.err, readers.ErrUnsupportedPlatform):
				failed++
				p.log.Warn("reader unavailable on this platform", "reader", res.name)
			default:
				failed++
				p.log.Error("reader failed", "reader", res.name, "err", res.err)
			}
			if running == 0 && ctx.Err() == nil {
				if failed == len(rs) {
					runErr = ErrNoReader
				}
				break loop
			}
		}
	}

	// Shutdown: stop readers, drain what is already queued, flush, persist.
	stopReaders()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		p.log.Warn("readers did not stop in time")
	}
drain:
	for {
		select {
		case ev := <-queue:
			p.handle(ev)
		default:
			break drain
		}
	}
	p.flushDirty(p.clk.Now(), true)
	p.maintain(p.clk.Now())
	p.saveState()
	p.log.Info("whotyped stopped", "dropped_events", p.dropped.Load(), "tracks", len(p.corr.Tracks()))
	return runErr
}
