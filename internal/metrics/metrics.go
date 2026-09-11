// Package metrics is a small, dependency-free Prometheus text exposition
// (format 0.0.4) with the counters and gauges whotyped publishes.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type kind string

const (
	kindCounter kind = "counter"
	kindGauge   kind = "gauge"
)

type metric struct {
	name   string
	help   string
	kind   kind
	labels []string

	mu     sync.Mutex
	series map[string]*series // keyed by the rendered label set
}

type series struct {
	values []string
	v      float64
}

// Registry holds metrics and renders them. The zero value is ready to use.
type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*metric
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) register(name, help string, k kind, labels []string) *metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metrics == nil {
		r.metrics = map[string]*metric{}
	}
	if m, ok := r.metrics[name]; ok {
		if m.kind != k || strings.Join(m.labels, ",") != strings.Join(labels, ",") {
			panic(fmt.Sprintf("metrics: %s re-registered with a different type or label set", name))
		}
		return m
	}
	m := &metric{name: name, help: help, kind: k, labels: append([]string(nil), labels...), series: map[string]*series{}}
	r.metrics[name] = m
	return m
}

// Counter registers (or fetches) a monotonically increasing metric.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{m: r.register(name, help, kindCounter, labels)}
}

// Gauge registers (or fetches) a metric that can go up and down.
func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	return &Gauge{m: r.register(name, help, kindGauge, labels)}
}

// Counter is a cumulative metric.
type Counter struct{ m *metric }

// Inc adds 1 to the series identified by labelValues.
func (c *Counter) Inc(labelValues ...string) { c.m.add(1, labelValues) }

// Add adds v (>= 0) to the series.
func (c *Counter) Add(v float64, labelValues ...string) {
	if v >= 0 {
		c.m.add(v, labelValues)
	}
}

// Set overwrites the cumulative value. Use it to mirror a counter kept
// elsewhere (the dispatcher's per-sink totals), never to go backwards.
func (c *Counter) Set(v float64, labelValues ...string) { c.m.set(v, labelValues, true) }

// Gauge is an instantaneous value.
type Gauge struct{ m *metric }

// Set stores v for the series.
func (g *Gauge) Set(v float64, labelValues ...string) { g.m.set(v, labelValues, false) }

// Inc adds 1.
func (g *Gauge) Inc(labelValues ...string) { g.m.add(1, labelValues) }

// Dec subtracts 1.
func (g *Gauge) Dec(labelValues ...string) { g.m.add(-1, labelValues) }

// Add adds v (may be negative).
func (g *Gauge) Add(v float64, labelValues ...string) { g.m.add(v, labelValues) }

// Get returns the current value of a series (0 if absent). Handy in tests.
func (g *Gauge) Get(labelValues ...string) float64 { return g.m.get(labelValues) }

// Get returns the current value of a series (0 if absent). Handy in tests.
func (c *Counter) Get(labelValues ...string) float64 { return c.m.get(labelValues) }

func (m *metric) key(values []string) string {
	if len(values) != len(m.labels) {
		panic(fmt.Sprintf("metrics: %s expects %d label values, got %d", m.name, len(m.labels), len(values)))
	}
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	for i, l := range m.labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(values[i]))
		b.WriteByte('"')
	}
	return b.String()
}

func (m *metric) add(v float64, values []string) {
	k := m.key(values)
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.series[k]
	if s == nil {
		s = &series{values: append([]string(nil), values...)}
		m.series[k] = s
	}
	s.v += v
}

func (m *metric) set(v float64, values []string, monotonic bool) {
	k := m.key(values)
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.series[k]
	if s == nil {
		s = &series{values: append([]string(nil), values...)}
		m.series[k] = s
	}
	if monotonic && v < s.v {
		return
	}
	s.v = v
}

func (m *metric) get(values []string) float64 {
	k := m.key(values)
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.series[k]; s != nil {
		return s.v
	}
	return 0
}

// ---------------------------------------------------------------------------
// Rendering

// escapeLabel escapes a label value per the exposition format.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes HELP text (only backslash and newline).
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// WriteTo renders every metric, sorted by name then label set.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	ms := make([]*metric, 0, len(names))
	sort.Strings(names)
	for _, n := range names {
		ms = append(ms, r.metrics[n])
	}
	r.mu.RUnlock()

	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", m.name, escapeHelp(m.help), m.name, m.kind)
		m.mu.Lock()
		keys := make([]string, 0, len(m.series))
		for k := range m.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(&b, "%s %s\n", m.name, formatValue(m.series[k].v))
			} else {
				fmt.Fprintf(&b, "%s{%s} %s\n", m.name, k, formatValue(m.series[k].v))
			}
		}
		m.mu.Unlock()
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// String renders the registry (tests and debugging).
func (r *Registry) String() string {
	var b strings.Builder
	_, _ = r.WriteTo(&b)
	return b.String()
}

// Handler serves the exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = r.WriteTo(w)
	})
}

// Serve listens on listen (host:port) and serves /metrics and /healthz until
// ctx is done. It returns nil after a clean shutdown.
func (r *Registry) Serve(ctx context.Context, listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("metrics: listen %s: %w", listen, err)
	}
	return r.ServeListener(ctx, ln)
}

// ServeListener is Serve on an existing listener (tests pick port 0).
func (r *Registry) ServeListener(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", r.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errc
		return nil
	}
}

// ---------------------------------------------------------------------------
// whotyped's metric set

// Standard bundles the metrics the daemon publishes.
type Standard struct {
	BuildInfo          *Gauge   // whotyped_build_info{version,commit} 1
	EventsTotal        *Counter // whotyped_events_total{kind}
	EventsDroppedTotal *Counter // whotyped_events_dropped_total
	TracksOpen         *Gauge   // whotyped_tracks_open
	AlertsTotal        *Counter // whotyped_alerts_total{level,class}
	SinkSentTotal      *Counter // whotyped_sink_sent_total{sink}
	SinkFailedTotal    *Counter // whotyped_sink_failed_total{sink}
	SinkDroppedTotal   *Counter // whotyped_sink_dropped_total{sink}
	ReaderUp           *Gauge   // whotyped_reader_up{name}
	LastEventTimestamp *Gauge   // whotyped_last_event_timestamp_seconds{source}
}

// NewStandard registers the metric set on r and stamps build_info.
func NewStandard(r *Registry, version, commit string) *Standard {
	s := &Standard{
		BuildInfo:          r.Gauge("whotyped_build_info", "Build information; always 1.", "version", "commit"),
		EventsTotal:        r.Counter("whotyped_events_total", "Events received from readers, by kind.", "kind"),
		EventsDroppedTotal: r.Counter("whotyped_events_dropped_total", "Events dropped because the pipeline channel was full."),
		TracksOpen:         r.Gauge("whotyped_tracks_open", "Tracks currently open in the correlator."),
		AlertsTotal:        r.Counter("whotyped_alerts_total", "Alerts emitted by the dispatcher, by level and class.", "level", "class"),
		SinkSentTotal:      r.Counter("whotyped_sink_sent_total", "Alerts delivered per sink.", "sink"),
		SinkFailedTotal:    r.Counter("whotyped_sink_failed_total", "Alerts that failed delivery after retries, per sink.", "sink"),
		SinkDroppedTotal:   r.Counter("whotyped_sink_dropped_total", "Alerts evicted from a full sink queue, per sink.", "sink"),
		ReaderUp:           r.Gauge("whotyped_reader_up", "1 while the named reader is running.", "name"),
		LastEventTimestamp: r.Gauge("whotyped_last_event_timestamp_seconds", "Unix time of the last event seen, by source.", "source"),
	}
	s.BuildInfo.Set(1, version, commit)
	return s
}

// SinkStats mirrors alert.SinkStats without importing it, so metrics stays a
// leaf package; the daemon copies the dispatcher's Stats() into it.
type SinkStats struct{ Sent, Failed, Dropped int }

// SetSinkStats copies cumulative per-sink counters into the registry.
func (s *Standard) SetSinkStats(stats map[string]SinkStats) {
	for name, st := range stats {
		s.SinkSentTotal.Set(float64(st.Sent), name)
		s.SinkFailedTotal.Set(float64(st.Failed), name)
		s.SinkDroppedTotal.Set(float64(st.Dropped), name)
	}
}
