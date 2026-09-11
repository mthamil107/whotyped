package alert

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
	"github.com/whotyped/whotyped/internal/session"
)

// fakeSink records alerts. entered is signalled on every Send; gate, when
// non-nil, blocks Send until closed (or ctx is done). fail scripts errors:
// each Send pops the next one until the slice is empty.
type fakeSink struct {
	name    string
	mu      sync.Mutex
	got     []Alert
	calls   int
	fail    []error
	gate    chan struct{}
	entered chan struct{}
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Send(ctx context.Context, a Alert) error {
	f.mu.Lock()
	f.calls++
	var err error
	if len(f.fail) > 0 {
		err, f.fail = f.fail[0], f.fail[1:]
	}
	gate := f.gate
	f.mu.Unlock()
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.got = append(f.got, a)
	f.mu.Unlock()
	return nil
}

func (f *fakeSink) events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.got))
	for i, a := range f.got {
		out[i] = a.Event + "/" + string(a.Level)
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)} }
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func newTrack() *session.Track {
	return &session.Track{
		ID:  "tr_test0001",
		Key: session.TrackKey{User: "alice", Fingerprint: "-", SrcIP: "10.0.0.5"},
		Connections: []*session.Connection{
			{ID: "c1", User: "alice", SrcIP: "10.0.0.5", SrcPort: 51000, Fingerprint: "SHA256:abc"},
		},
		Execs:     []session.ExecSample{{Argv0: "ls"}, {Argv0: "cat"}},
		Mode:      "remote_agent",
		FirstSeen: time.Date(2026, 9, 11, 13, 50, 0, 0, time.UTC),
		LastSeen:  time.Date(2026, 9, 11, 14, 5, 0, 0, time.UTC),
	}
}

func suspected(s int) score.Verdict {
	v := score.Verdict{Score: s, Class: score.ClassSuspected, Mode: "remote_agent",
		Reasons: []clues.Clue{{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20, Evidence: "14 exec channels"}}}
	switch {
	case s >= 90:
		v.Level = score.LevelHigh
	case s >= 70:
		v.Level = score.LevelAlert
	case s >= 40:
		v.Level = score.LevelInfo
	default:
		v.Level = score.LevelNone
		v.Class = score.ClassHuman
	}
	return v
}

func newTestDispatcher(c *clock, sinks ...*fakeSink) *Dispatcher {
	d := New(Options{
		Host:         "web-03",
		Now:          c.now,
		RetryBackoff: []time.Duration{time.Millisecond, time.Millisecond},
	})
	for _, s := range sinks {
		d.Register(s, score.LevelInfo, 8)
	}
	d.Start(context.Background())
	return d
}

func flat(as []Alert) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Event + "/" + string(a.Level)
	}
	return out
}

func TestThresholdCrossingSequence(t *testing.T) {
	c := newClock()
	sink := &fakeSink{name: "fake"}
	d := newTestDispatcher(c, sink)
	tr := newTrack()

	var got []string
	for _, s := range []int{30, 45, 75, 95, 95} {
		got = append(got, flat(d.Observe(tr, suspected(s), nil))...)
		c.advance(time.Minute)
	}
	want := "agent_detected/info agent_detected/alert agent_high/high"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v want %s", got, want)
	}
	if tr.MaxLevel != "high" || tr.LastScore != 95 {
		t.Fatalf("bookkeeping: max=%q last=%d", tr.MaxLevel, tr.LastScore)
	}
	d.Close()
	if ev := strings.Join(sink.events(), " "); ev != want {
		t.Fatalf("sink got %s want %s", ev, want)
	}
	if st := d.Stats()["fake"]; st.Sent != 3 || st.Failed != 0 || st.Dropped != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestDirectJumpEmitsOnlyHighest(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	got := flat(d.Observe(newTrack(), suspected(95), nil))
	if len(got) != 1 || got[0] != "agent_high/high" {
		t.Fatalf("got %v", got)
	}
}

func TestStillActiveCadence(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	tr := newTrack()
	if got := flat(d.Observe(tr, suspected(75), nil)); len(got) != 1 {
		t.Fatalf("first: %v", got)
	}
	var got []string
	for i := 0; i < 9; i++ { // 10-minute ticks over 90 minutes
		c.advance(10 * time.Minute)
		got = append(got, flat(d.Observe(tr, suspected(80), nil))...)
	}
	// 30, 60, 90 minutes after the first alert.
	if strings.Join(got, " ") != "agent_still_active/alert agent_still_active/alert agent_still_active/alert" {
		t.Fatalf("got %v", got)
	}
	// Drops below alert: no still_active even after the interval.
	c.advance(time.Hour)
	if got := d.Observe(tr, suspected(50), nil); len(got) != 0 {
		t.Fatalf("below alert emitted %v", flat(got))
	}
}

func TestDeclaredOnce(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	tr := newTrack()
	tr.DeclaredAgent = "claude-code"
	v := score.Verdict{Score: 12, Class: score.ClassDeclared, Level: score.LevelInfo, Agent: "claude-code", Mode: "remote_agent"}
	first := d.Observe(tr, v, nil)
	if len(first) != 1 || first[0].Event != EvDeclared || first[0].Level != score.LevelInfo {
		t.Fatalf("first %v", flat(first))
	}
	if !strings.Contains(first[0].ActionsHint, "Declared agent claude-code") {
		t.Fatalf("hint %q", first[0].ActionsHint)
	}
	c.advance(2 * time.Hour)
	if again := d.Observe(tr, v, nil); len(again) != 0 {
		t.Fatalf("declared repeated: %v", flat(again))
	}
	if tr.MaxLevel != "info" {
		t.Fatalf("max level %q", tr.MaxLevel)
	}
	// A declared track never reaches alert, so no agent_ended.
	if a := d.Ended(tr); a != nil {
		t.Fatalf("ended emitted %v", a.Event)
	}
}

func TestFreezeViolation(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	fz := &Freeze{Name: "release-2026-09", Until: c.t.Add(4 * time.Hour)}

	// Declared agent inside a freeze: violation at high, not agent_declared.
	tr := newTrack()
	v := score.Verdict{Score: 5, Class: score.ClassDeclared, Level: score.LevelInfo, Agent: "claude-code"}
	got := d.Observe(tr, v, fz)
	if len(got) != 1 || got[0].Event != EvFreeze || got[0].Level != score.LevelHigh {
		t.Fatalf("got %v", flat(got))
	}
	if got[0].FreezeWindow == nil || got[0].FreezeWindow.Name != fz.Name {
		t.Fatalf("freeze window not attached: %+v", got[0].FreezeWindow)
	}
	if !strings.Contains(got[0].ActionsHint, "freeze window release-2026-09") {
		t.Fatalf("hint %q", got[0].ActionsHint)
	}
	// Same freeze, shortly after: quiet. After the interval: still_active.
	c.advance(time.Minute)
	if again := d.Observe(tr, v, fz); len(again) != 0 {
		t.Fatalf("repeated violation %v", flat(again))
	}
	c.advance(30 * time.Minute)
	if again := flat(d.Observe(tr, v, fz)); len(again) != 1 || again[0] != "agent_still_active/high" {
		t.Fatalf("cadence %v", again)
	}
	// A different freeze window on the same track: a new violation.
	fz2 := &Freeze{Name: "hotfix", Until: c.t.Add(time.Hour)}
	if again := flat(d.Observe(tr, v, fz2)); len(again) != 1 || again[0] != "freeze_violation/high" {
		t.Fatalf("second freeze %v", again)
	}
	// Reached high via the freeze, so it ends loudly.
	if a := d.Ended(tr); a == nil || a.Event != EvEnded {
		t.Fatalf("ended: %+v", a)
	}

	// Suspected at info inside a freeze is also a violation; human is not.
	tr2 := newTrack()
	tr2.ID = "tr_test0002"
	if got := flat(d.Observe(tr2, suspected(45), fz)); len(got) != 1 || got[0] != "freeze_violation/high" {
		t.Fatalf("suspected in freeze %v", got)
	}
	tr3 := newTrack()
	tr3.ID = "tr_test0003"
	if got := d.Observe(tr3, suspected(10), fz); len(got) != 0 {
		t.Fatalf("human in freeze %v", flat(got))
	}
}

func TestEndedOnlyIfReachedAlert(t *testing.T) {
	c := newClock()
	sink := &fakeSink{name: "fake"}
	d := newTestDispatcher(c, sink)

	quiet := newTrack()
	d.Observe(quiet, suspected(45), nil)
	if a := d.Ended(quiet); a != nil {
		t.Fatalf("info-only track ended: %v", a.Event)
	}

	loud := newTrack()
	loud.ID = "tr_loud"
	d.Observe(loud, suspected(75), nil)
	a := d.Ended(loud)
	if a == nil || a.Event != EvEnded || a.Level != score.LevelAlert || a.SessionID != "tr_loud" {
		t.Fatalf("ended: %+v", a)
	}
	d.Close()
	if ev := strings.Join(sink.events(), " "); ev != "agent_detected/info agent_detected/alert agent_ended/alert" {
		t.Fatalf("sink %s", ev)
	}
}

func TestMinLevelFilter(t *testing.T) {
	c := newClock()
	info := &fakeSink{name: "info"}
	high := &fakeSink{name: "high"}
	d := New(Options{Host: "h", Now: c.now})
	d.Register(info, score.LevelInfo, 4)
	d.Register(high, score.LevelHigh, 4)
	d.Start(context.Background())
	tr := newTrack()
	for _, s := range []int{45, 75, 95} {
		d.Observe(tr, suspected(s), nil)
	}
	d.Close()
	if len(info.got) != 3 || len(high.got) != 1 || high.got[0].Event != EvHigh {
		t.Fatalf("info=%v high=%v", info.events(), high.events())
	}
}

func TestQueueOverflowDropsOldest(t *testing.T) {
	c := newClock()
	sink := &fakeSink{name: "slow", gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	d := New(Options{Host: "h", Now: c.now})
	d.Register(sink, score.LevelInfo, 2)
	d.Start(context.Background())

	// First alert is pulled into Send and blocks there; the queue is empty.
	tr := newTrack()
	d.Observe(tr, suspected(45), nil)
	<-sink.entered
	// Four more: queue holds two, the two oldest of those are evicted.
	for i := 0; i < 4; i++ {
		c.advance(31 * time.Minute)
		tr.MaxLevel = "" // force a fresh crossing each time
		d.Observe(tr, suspected(75+i), nil)
	}
	waitFor(t, func() bool { return d.Stats()["slow"].Dropped == 2 })
	close(sink.gate)
	waitFor(t, func() bool { return d.Stats()["slow"].Sent == 3 })
	d.Close()
	// The survivors are the newest two plus the one that was in flight.
	got := sink.events()
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	sink.mu.Lock()
	last := sink.got[2].Score
	sink.mu.Unlock()
	if last != 78 {
		t.Fatalf("newest alert lost; last score %d", last)
	}
}

func TestRetryTransientThenPermanent(t *testing.T) {
	c := newClock()
	flaky := &fakeSink{name: "flaky", fail: []error{ErrTransient, errWrap{ErrTransient}}}
	perm := &fakeSink{name: "perm", fail: []error{errors.New("400 bad request")}}
	giveup := &fakeSink{name: "giveup", fail: []error{ErrTransient, ErrTransient, ErrTransient, ErrTransient}}
	d := New(Options{Host: "h", Now: c.now, RetryBackoff: []time.Duration{time.Millisecond, time.Millisecond}})
	for _, s := range []*fakeSink{flaky, perm, giveup} {
		d.Register(s, score.LevelInfo, 4)
	}
	d.Start(context.Background())
	d.Observe(newTrack(), suspected(75), nil)
	d.Close()
	st := d.Stats()
	if st["flaky"].Sent != 1 || st["flaky"].Failed != 0 || flaky.calls != 3 {
		t.Fatalf("flaky %+v calls=%d", st["flaky"], flaky.calls)
	}
	if st["perm"].Failed != 1 || perm.calls != 1 {
		t.Fatalf("perm %+v calls=%d", st["perm"], perm.calls)
	}
	if st["giveup"].Failed != 1 || giveup.calls != 3 {
		t.Fatalf("giveup %+v calls=%d", st["giveup"], giveup.calls)
	}
}

type errWrap struct{ err error }

func (e errWrap) Error() string { return "http: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

func TestBuildFillsSchema(t *testing.T) {
	c := newClock()
	d := New(Options{Host: "web-03", Now: c.now})
	tr := newTrack()
	v := suspected(82)
	v.Suppressed = nil
	a := d.Build(tr, v, EvDetected, nil)

	if a.Schema != Schema || a.Host != "web-03" || a.User != "alice" || a.SrcIP != "10.0.0.5" {
		t.Fatalf("header fields: %+v", a)
	}
	if a.KeyFingerprint != "SHA256:abc" {
		t.Fatalf("fingerprint should fall back to the connection: %q", a.KeyFingerprint)
	}
	if a.Mode != "remote_agent" || a.Connections != 1 || a.Window.Execs != 2 || a.SessionID != tr.ID {
		t.Fatalf("body fields: %+v", a)
	}
	if !a.Window.End.Equal(tr.LastSeen) || !a.Window.Start.Equal(tr.LastSeen.Add(-15*time.Minute)) {
		t.Fatalf("window %+v", a.Window)
	}
	if !strings.Contains(a.ActionsHint, "Ask alice whether an AI tool") || !strings.Contains(a.ActionsHint, "--session tr_test0001") {
		t.Fatalf("hint %q", a.ActionsHint)
	}
	// Reasons are copied, not aliased.
	v.Reasons[0].Evidence = "mutated"
	if a.Reasons[0].Evidence == "mutated" {
		t.Fatal("reasons aliased the verdict slice")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema":"whotyped.alert.v1"`, `"suppressed":[]`, `"freeze_window":null`, `"key_fingerprint":"SHA256:abc"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("json missing %s: %s", want, raw)
		}
	}
}

func TestDedupeRoundTrip(t *testing.T) {
	c := newClock()
	d := newTestDispatcher(c)
	tr := newTrack()
	tr.DeclaredAgent = "bot"
	v := score.Verdict{Class: score.ClassDeclared, Level: score.LevelInfo, Agent: "bot"}
	d.Observe(tr, v, nil)
	fz := &Freeze{Name: "fz", Until: c.t.Add(time.Hour)}
	tr2 := newTrack()
	tr2.ID = "tr_two"
	d.Observe(tr2, suspected(50), fz)

	saved := d.Dedupe()
	if len(saved) != 2 {
		t.Fatalf("dedupe %v", saved)
	}
	// A fresh dispatcher restored from the snapshot stays quiet.
	d2 := newTestDispatcher(c)
	d2.Restore(saved)
	if got := d2.Observe(tr, v, nil); len(got) != 0 {
		t.Fatalf("declared re-emitted after restore: %v", flat(got))
	}
	if got := d2.Observe(tr2, suspected(50), fz); len(got) != 0 {
		t.Fatalf("freeze re-emitted after restore: %v", flat(got))
	}
}

func TestIsTransient(t *testing.T) {
	if !IsTransient(ErrTransient) || !IsTransient(errWrap{ErrTransient}) || !IsTransient(context.DeadlineExceeded) {
		t.Fatal("transient errors not recognised")
	}
	if IsTransient(nil) || IsTransient(errors.New("400")) {
		t.Fatal("permanent errors misclassified")
	}
}

func TestHashUsernames(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 9, 11, 14, 5, 0, 0, time.UTC) }
	d := New(Options{Host: "web-03", HashUsernames: true, HashSalt: "pepper", Now: now})
	a := d.Build(newTrack(), suspected(75), EvDetected, nil)
	want := HashUser("pepper", "alice")
	if a.User != want || !strings.HasPrefix(a.User, "u_") || len(a.User) != 14 {
		t.Fatalf("user %q, want %q", a.User, want)
	}
	if strings.Contains(a.ActionsHint, "alice") || !strings.Contains(a.ActionsHint, "the key owner") {
		t.Errorf("actions_hint leaks or misses: %q", a.ActionsHint)
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "alice") {
		t.Errorf("serialised alert still carries the raw user: %s", b)
	}
	// Deterministic, salt-sensitive, and the salt defaults to the host.
	if HashUser("pepper", "alice") != want || HashUser("salt2", "alice") == want || HashUser("pepper", "bob") == want {
		t.Error("HashUser must be a deterministic salted hash")
	}
	d2 := New(Options{Host: "web-03", HashUsernames: true, Now: now})
	if a2 := d2.Build(newTrack(), suspected(75), EvDetected, nil); a2.User != HashUser("web-03", "alice") {
		t.Errorf("salt should default to host: %q", a2.User)
	}
	// Off by default: the raw name is kept and the hint addresses it.
	d3 := New(Options{Host: "web-03", Now: now})
	if a3 := d3.Build(newTrack(), suspected(75), EvDetected, nil); a3.User != "alice" || !strings.Contains(a3.ActionsHint, "Ask alice") {
		t.Errorf("hashing must be opt-in: %q %q", a3.User, a3.ActionsHint)
	}
}
