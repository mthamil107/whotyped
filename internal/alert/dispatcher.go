package alert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
	"github.com/whotyped/whotyped/internal/session"
)

// ErrTransient marks a delivery failure worth retrying (5xx, timeouts,
// connection resets). Sinks wrap it: fmt.Errorf("%w: status 503", ErrTransient).
// It lives here rather than in a sink package so the dispatcher can test for
// it without importing every sink.
var ErrTransient = errors.New("transient sink error")

// IsTransient reports whether err should be retried.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTransient) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// Options configures a Dispatcher. Zero values pick the design defaults.
type Options struct {
	Host            string
	RealertInterval time.Duration    // agent_still_active cadence; default 30m
	Window          time.Duration    // scoring window reported in Alert.Window; default 15m
	Thresholds      score.Thresholds // used only when a Verdict carries no Level
	Now             func() time.Time
	Logger          *slog.Logger
	// RetryBackoff are the waits between delivery attempts. Its length plus
	// one is the attempt count. Default 2s, 8s (three attempts).
	RetryBackoff []time.Duration
	// SendTimeout bounds one Send call on a sink; default 30s.
	SendTimeout time.Duration
	// HashUsernames replaces Alert.User with HashUser(HashSalt, user) and
	// keeps the raw name out of actions_hint (privacy.hash_usernames).
	// HashSalt defaults to Host, so the same user hashes differently per
	// host unless operators set one salt fleet-wide.
	HashUsernames bool
	HashSalt      string
}

// HashUser returns the pseudonym used when HashUsernames is set:
// "u_" + first 12 hex digits of sha256(salt + user). 48 bits is plenty to
// tell users on one fleet apart and short enough to read in a Slack card;
// the salt keeps a dictionary of local account names from reversing it.
func HashUser(salt, user string) string {
	sum := sha256.Sum256([]byte(salt + user))
	return "u_" + hex.EncodeToString(sum[:6])
}

// SinkStats counts what happened to alerts routed to one sink.
type SinkStats struct {
	Sent    int
	Failed  int // gave up after retries (or permanent error)
	Dropped int // evicted from a full queue, or enqueued after Close
}

// trackMemo is dispatcher-private per-track bookkeeping that has no home on
// session.Track: whether agent_declared went out, and which freeze window
// already produced a freeze_violation. It is exported through Dedupe() so the
// state file can carry it across restarts.
type trackMemo struct {
	declaredAt time.Time
	freezeName string
	freezeAt   time.Time
}

// Dispatcher applies the re-alert policy and fans alerts out to sinks.
// Observe/Ended are expected from the correlator goroutine but are safe to
// call concurrently; they never block on a slow sink.
type Dispatcher struct {
	opts Options
	log  *slog.Logger

	mu      sync.Mutex // sinks, started, closed
	sinks   []*sinkWorker
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	tm    sync.Mutex // memos
	memos map[string]*trackMemo
}

// New builds a Dispatcher. Call Register for each sink, then Start.
func New(opts Options) *Dispatcher {
	if opts.RealertInterval <= 0 {
		opts.RealertInterval = 30 * time.Minute
	}
	if opts.Window <= 0 {
		opts.Window = 15 * time.Minute
	}
	if opts.Thresholds == (score.Thresholds{}) {
		opts.Thresholds = score.DefaultThresholds
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.RetryBackoff == nil {
		opts.RetryBackoff = []time.Duration{2 * time.Second, 8 * time.Second}
	}
	if opts.SendTimeout <= 0 {
		opts.SendTimeout = 30 * time.Second
	}
	if opts.HashSalt == "" {
		opts.HashSalt = opts.Host
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{
		opts:   opts,
		log:    opts.Logger.With("component", "dispatcher"),
		ctx:    ctx,
		cancel: cancel,
		memos:  map[string]*trackMemo{},
	}
}

// ---------------------------------------------------------------------------
// Sinks

type sinkWorker struct {
	sink     Sink
	minLevel score.Level
	ch       chan Alert

	qmu sync.Mutex // serialises enqueue so drop-oldest is atomic
	smu sync.Mutex
	st  SinkStats
}

// Register attaches a sink that receives alerts at or above minLevel. queue is
// the bounded channel size (<=0 means 64). When the queue is full the oldest
// alert is evicted and counted as dropped; the caller is never blocked.
func (d *Dispatcher) Register(s Sink, minLevel score.Level, queue int) {
	if queue <= 0 {
		queue = 64
	}
	w := &sinkWorker{sink: s, minLevel: minLevel, ch: make(chan Alert, queue)}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sinks = append(d.sinks, w)
	if d.started && !d.closed {
		d.wg.Add(1)
		go d.run(w)
	}
}

// Start launches one goroutine per registered sink. ctx cancellation aborts
// in-flight deliveries; use Close to flush gracefully.
func (d *Dispatcher) Start(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started || d.closed {
		return
	}
	d.started = true
	d.cancel() // discard the placeholder context from New
	d.ctx, d.cancel = context.WithCancel(ctx)
	for _, w := range d.sinks {
		d.wg.Add(1)
		go d.run(w)
	}
}

// Close stops accepting alerts and waits up to 5s for queues to drain, then
// cancels anything still in flight.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	for _, w := range d.sinks {
		close(w.ch)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		d.log.Warn("sink flush deadline exceeded; cancelling in-flight deliveries")
	}
	d.cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		d.log.Warn("sink goroutines did not exit after cancel")
	}
}

// Stats returns a snapshot of per-sink counters keyed by sink name.
func (d *Dispatcher) Stats() map[string]SinkStats {
	d.mu.Lock()
	sinks := append([]*sinkWorker(nil), d.sinks...)
	d.mu.Unlock()
	out := make(map[string]SinkStats, len(sinks))
	for _, w := range sinks {
		name := w.sink.Name()
		for i := 2; ; i++ {
			if _, dup := out[name]; !dup {
				break
			}
			name = fmt.Sprintf("%s#%d", w.sink.Name(), i)
		}
		w.smu.Lock()
		out[name] = w.st
		w.smu.Unlock()
	}
	return out
}

func (d *Dispatcher) fanout(a Alert) {
	d.mu.Lock()
	closed := d.closed
	sinks := append([]*sinkWorker(nil), d.sinks...)
	d.mu.Unlock()
	for _, w := range sinks {
		if a.Level.Rank() < w.minLevel.Rank() {
			continue
		}
		if closed {
			w.bump(func(s *SinkStats) { s.Dropped++ })
			continue
		}
		w.enqueue(a)
	}
}

func (w *sinkWorker) enqueue(a Alert) {
	w.qmu.Lock()
	defer w.qmu.Unlock()
	select {
	case w.ch <- a:
		return
	default:
	}
	// Full: evict the oldest so the newest alert survives.
	select {
	case <-w.ch:
		w.bump(func(s *SinkStats) { s.Dropped++ })
	default:
	}
	select {
	case w.ch <- a:
	default:
		w.bump(func(s *SinkStats) { s.Dropped++ })
	}
}

func (w *sinkWorker) bump(f func(*SinkStats)) {
	w.smu.Lock()
	f(&w.st)
	w.smu.Unlock()
}

func (d *Dispatcher) run(w *sinkWorker) {
	defer d.wg.Done()
	for {
		select {
		case a, ok := <-w.ch:
			if !ok {
				return
			}
			d.deliver(w, a)
		case <-d.ctx.Done():
			return
		}
	}
}

// deliver tries Send up to len(RetryBackoff)+1 times, sleeping between
// attempts only for transient errors.
func (d *Dispatcher) deliver(w *sinkWorker, a Alert) {
	var err error
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(d.ctx, d.opts.SendTimeout)
		err = w.sink.Send(ctx, a)
		cancel()
		if err == nil {
			w.bump(func(s *SinkStats) { s.Sent++ })
			return
		}
		if d.ctx.Err() != nil || attempt >= len(d.opts.RetryBackoff) || !IsTransient(err) {
			break
		}
		d.log.Debug("sink send failed; retrying", "sink", w.sink.Name(), "attempt", attempt+1, "err", err)
		select {
		case <-time.After(d.opts.RetryBackoff[attempt]):
		case <-d.ctx.Done():
		}
	}
	w.bump(func(s *SinkStats) { s.Failed++ })
	d.log.Warn("sink send failed", "sink", w.sink.Name(), "event", a.Event, "session", a.SessionID, "err", err)
}

// ---------------------------------------------------------------------------
// Policy

// Observe applies the re-alert policy to a fresh verdict, updates the track's
// bookkeeping fields (MaxLevel, LastAlert, LastScore) and fans out whatever it
// emitted. The returned slice is what went to the sinks (nil when quiet).
func (d *Dispatcher) Observe(t *session.Track, v score.Verdict, freeze *Freeze) []Alert {
	if t == nil {
		return nil
	}
	now := d.opts.Now()
	if v.Level == "" {
		v.Level = d.levelFor(v.Score)
	}
	memo := d.memo(t.ID)
	prev := score.Level(t.MaxLevel)
	var out []Alert
	emit := func(ev string) {
		a := d.Build(t, v, ev, freeze)
		a.TS = now
		out = append(out, a)
		t.LastAlert = now
		if a.Level.Rank() > prev.Rank() {
			t.MaxLevel = string(a.Level)
		}
	}
	defer func() {
		t.LastScore = v.Score
		for _, a := range out {
			d.fanout(a)
		}
	}()

	// Freeze window: declared or >=info suspected activity is a violation.
	if freeze != nil {
		violating := v.Class == score.ClassDeclared ||
			(v.Class != score.ClassHuman && v.Level.Rank() >= score.LevelInfo.Rank())
		if violating {
			d.tm.Lock()
			seen := memo.freezeName == freeze.Name && memo.freezeAt.Equal(freeze.Until)
			if !seen {
				memo.freezeName, memo.freezeAt = freeze.Name, freeze.Until
			}
			d.tm.Unlock()
			if !seen {
				emit(EvFreeze)
			} else if now.Sub(t.LastAlert) >= d.opts.RealertInterval {
				emit(EvStillActive)
			}
			return out
		}
	}

	// Declared agents: one agent_declared per track, at info.
	if v.Class == score.ClassDeclared {
		d.tm.Lock()
		done := !memo.declaredAt.IsZero()
		if !done {
			memo.declaredAt = now
		}
		d.tm.Unlock()
		if !done {
			emit(EvDeclared)
		}
		return out
	}

	// Suspected agents: threshold crossings, then still_active cadence.
	if v.Level.Rank() < score.LevelInfo.Rank() {
		return out
	}
	switch {
	case v.Level.Rank() > prev.Rank():
		if v.Level == score.LevelHigh {
			emit(EvHigh)
		} else {
			emit(EvDetected)
		}
	case v.Level.Rank() >= score.LevelAlert.Rank() && now.Sub(t.LastAlert) >= d.opts.RealertInterval:
		emit(EvStillActive)
	}
	return out
}

// Ended emits agent_ended for a track that ever reached alert (or high) and
// forgets its memo. Returns nil for tracks that never got that far.
func (d *Dispatcher) Ended(t *session.Track) *Alert {
	if t == nil {
		return nil
	}
	d.tm.Lock()
	delete(d.memos, t.ID)
	d.tm.Unlock()
	max := score.Level(t.MaxLevel)
	if max.Rank() < score.LevelAlert.Rank() {
		return nil
	}
	class := score.ClassSuspected
	if t.DeclaredAgent != "" {
		class = score.ClassDeclared
	}
	v := score.Verdict{
		Score: t.LastScore,
		Class: class,
		Level: max,
		Mode:  t.Mode,
		Agent: t.DeclaredAgent,
	}
	a := d.Build(t, v, EvEnded, nil)
	d.fanout(a)
	return &a
}

// Build fills every field of the v1 schema for one event. It does not touch
// track bookkeeping; Observe/Ended do that.
func (d *Dispatcher) Build(t *session.Track, v score.Verdict, ev string, freeze *Freeze) Alert {
	now := d.opts.Now()
	level := v.Level
	if level == "" {
		level = d.levelFor(v.Score)
	}
	switch {
	case ev == EvFreeze, ev == EvStillActive && freeze != nil:
		// A freeze violation, and its follow-ups, are high regardless of score.
		level = score.LevelHigh
	case ev == EvDeclared:
		level = score.LevelInfo
	}
	user := t.Key.User
	srcIP := t.Key.SrcIP
	fp := t.Key.Fingerprint
	if fp == "-" {
		fp = ""
	}
	for _, c := range t.Connections {
		if c == nil {
			continue
		}
		if user == "" {
			user = c.User
		}
		if srcIP == "" {
			srcIP = c.SrcIP
		}
		if fp == "" {
			fp = c.Fingerprint
		}
	}
	if d.opts.HashUsernames && user != "" {
		user = HashUser(d.opts.HashSalt, user)
	}
	mode := v.Mode
	if mode == "" {
		mode = t.Mode
	}
	if mode == "" {
		mode = "unknown"
	}
	agent := v.Agent
	if agent == "" {
		agent = t.DeclaredAgent
	}
	end := t.LastSeen
	if end.IsZero() {
		end = now
	}
	a := Alert{
		Schema:         Schema,
		TS:             now,
		Host:           d.opts.Host,
		Event:          ev,
		Class:          v.Class,
		Mode:           mode,
		User:           user,
		SrcIP:          srcIP,
		KeyFingerprint: fp,
		Agent:          agent,
		Score:          v.Score,
		Level:          level,
		Reasons:        append(v.Reasons[:0:0], v.Reasons...),
		Suppressed:     append(v.Suppressed[:0:0], v.Suppressed...),
		SessionID:      t.ID,
		Connections:    len(t.Connections),
		Window: Window{
			Start: end.Add(-d.opts.Window),
			End:   end,
			Execs: len(t.Execs),
		},
	}
	// Marshal empty lists as [] rather than null; the schema example shows [].
	if a.Reasons == nil {
		a.Reasons = []clues.Clue{}
	}
	if a.Suppressed == nil {
		a.Suppressed = []score.Suppression{}
	}
	if freeze != nil {
		f := *freeze
		a.FreezeWindow = &f
	}
	a.ActionsHint = d.hint(a, freeze)
	return a
}

func (d *Dispatcher) hint(a Alert, freeze *Freeze) string {
	switch a.Event {
	case EvFreeze:
		return fmt.Sprintf("Agent activity during freeze window %s: consider ending session %s", freeze.Name, a.SessionID)
	case EvDeclared:
		name := a.Agent
		if name == "" {
			name = "(unnamed)"
		}
		return fmt.Sprintf("Declared agent %s; no action unless in a freeze window", name)
	case EvEnded:
		return fmt.Sprintf("Session %s ended after reaching level %s. Details: whotyped report --session %s", a.SessionID, a.Level, a.SessionID)
	}
	if a.Class == score.ClassDeclared {
		return fmt.Sprintf("Declared agent %s is still active. Details: whotyped report --session %s", a.Agent, a.SessionID)
	}
	who := a.User
	if d.opts.HashUsernames || who == "" {
		who = "the key owner" // never echo a name the alert itself withholds
	}
	return fmt.Sprintf("Ask %s whether an AI tool is driving this key. Honest agents can declare themselves with: ssh -o SetEnv=AI_AGENT=<name> … Details: whotyped report --session %s", who, a.SessionID)
}

func (d *Dispatcher) levelFor(s int) score.Level {
	th := d.opts.Thresholds
	switch {
	case s >= th.High:
		return score.LevelHigh
	case s >= th.Alert:
		return score.LevelAlert
	case s >= th.Info:
		return score.LevelInfo
	}
	return score.LevelNone
}

func (d *Dispatcher) memo(id string) *trackMemo {
	d.tm.Lock()
	defer d.tm.Unlock()
	m := d.memos[id]
	if m == nil {
		m = &trackMemo{}
		d.memos[id] = m
	}
	return m
}

// ---------------------------------------------------------------------------
// Dedupe persistence (state.Dedupe)

// Dedupe exports the per-track memos as flat keys suitable for state.State.
// Keys: "declared:<track>" and "freeze:<track>:<name>" mapped to the time the
// corresponding alert went out (freeze entries carry the window's Until).
func (d *Dispatcher) Dedupe() map[string]time.Time {
	d.tm.Lock()
	defer d.tm.Unlock()
	out := map[string]time.Time{}
	for id, m := range d.memos {
		if !m.declaredAt.IsZero() {
			out["declared:"+id] = m.declaredAt
		}
		if m.freezeName != "" {
			out["freeze:"+id+":"+m.freezeName] = m.freezeAt
		}
	}
	return out
}

// Restore loads memos previously produced by Dedupe. Unknown keys are ignored.
func (d *Dispatcher) Restore(m map[string]time.Time) {
	d.tm.Lock()
	defer d.tm.Unlock()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ts := m[k]
		if id, ok := strings.CutPrefix(k, "declared:"); ok && id != "" {
			d.memoLocked(id).declaredAt = ts
			continue
		}
		if rest, ok := strings.CutPrefix(k, "freeze:"); ok {
			// Track IDs carry no ':' so the first one separates id from name.
			id, name, found := strings.Cut(rest, ":")
			if !found || id == "" {
				continue
			}
			mm := d.memoLocked(id)
			mm.freezeName, mm.freezeAt = name, ts
		}
	}
}

func (d *Dispatcher) memoLocked(id string) *trackMemo {
	m := d.memos[id]
	if m == nil {
		m = &trackMemo{}
		d.memos[id] = m
	}
	return m
}
