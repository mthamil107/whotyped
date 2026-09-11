package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRenderFormat(t *testing.T) {
	r := NewRegistry()
	std := NewStandard(r, "0.1.0", "abc1234")
	std.EventsTotal.Inc("ssh.auth_ok")
	std.EventsTotal.Inc("ssh.auth_ok")
	std.EventsTotal.Inc("audit.execve")
	std.EventsDroppedTotal.Add(3)
	std.TracksOpen.Set(2)
	std.TracksOpen.Dec()
	std.AlertsTotal.Inc("alert", "suspected_agent")
	std.ReaderUp.Set(1, "sshlog")
	std.LastEventTimestamp.Set(1.7576e9, "sshlog")
	std.SetSinkStats(map[string]SinkStats{"jsonfile": {Sent: 5, Failed: 1, Dropped: 0}})

	out := r.String()
	want := strings.Join([]string{
		"# HELP whotyped_alerts_total Alerts emitted by the dispatcher, by level and class.",
		"# TYPE whotyped_alerts_total counter",
		`whotyped_alerts_total{level="alert",class="suspected_agent"} 1`,
		"# HELP whotyped_build_info Build information; always 1.",
		"# TYPE whotyped_build_info gauge",
		`whotyped_build_info{version="0.1.0",commit="abc1234"} 1`,
		"# HELP whotyped_events_dropped_total Events dropped because the pipeline channel was full.",
		"# TYPE whotyped_events_dropped_total counter",
		"whotyped_events_dropped_total 3",
		"# HELP whotyped_events_total Events received from readers, by kind.",
		"# TYPE whotyped_events_total counter",
		`whotyped_events_total{kind="audit.execve"} 1`,
		`whotyped_events_total{kind="ssh.auth_ok"} 2`,
		"# HELP whotyped_last_event_timestamp_seconds Unix time of the last event seen, by source.",
		"# TYPE whotyped_last_event_timestamp_seconds gauge",
		`whotyped_last_event_timestamp_seconds{source="sshlog"} 1757600000`,
		"# HELP whotyped_reader_up 1 while the named reader is running.",
		"# TYPE whotyped_reader_up gauge",
		`whotyped_reader_up{name="sshlog"} 1`,
		"# HELP whotyped_sink_dropped_total Alerts evicted from a full sink queue, per sink.",
		"# TYPE whotyped_sink_dropped_total counter",
		`whotyped_sink_dropped_total{sink="jsonfile"} 0`,
		"# HELP whotyped_sink_failed_total Alerts that failed delivery after retries, per sink.",
		"# TYPE whotyped_sink_failed_total counter",
		`whotyped_sink_failed_total{sink="jsonfile"} 1`,
		"# HELP whotyped_sink_sent_total Alerts delivered per sink.",
		"# TYPE whotyped_sink_sent_total counter",
		`whotyped_sink_sent_total{sink="jsonfile"} 5`,
		"# HELP whotyped_tracks_open Tracks currently open in the correlator.",
		"# TYPE whotyped_tracks_open gauge",
		"whotyped_tracks_open 1",
		"",
	}, "\n")
	if out != want {
		t.Fatalf("render mismatch\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

func TestLabelAndHelpEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("x_total", `help with \ backslash and
newline`, "l")
	c.Inc("quote\" backslash\\ newline\n end")
	out := r.String()
	wantSeries := `x_total{l="quote\" backslash\\ newline\n end"} 1`
	if !strings.Contains(out, wantSeries) {
		t.Fatalf("label escaping wrong:\n%s", out)
	}
	if !strings.Contains(out, `# HELP x_total help with \\ backslash and\nnewline`) {
		t.Fatalf("help escaping wrong:\n%s", out)
	}
}

func TestValueFormatting(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("v", "")
	cases := map[float64]string{0: "0", 42: "42", -3: "-3", 0.5: "0.5", 1e20: "1e+20", 1757600000.25: "1.75760000025e+09"}
	for v, want := range cases {
		g.Set(v)
		if !strings.Contains(r.String(), "\nv "+want+"\n") {
			t.Fatalf("value %v rendered as %q, want %s", v, r.String(), want)
		}
	}
}

func TestCounterSemantics(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "", "k")
	c.Add(-5, "a") // ignored
	c.Inc("a")
	c.Set(10, "a")
	c.Set(4, "a") // ignored: counters do not go backwards
	if got := c.Get("a"); got != 10 {
		t.Fatalf("counter value %v", got)
	}
	// Re-registering the same metric returns the same series.
	if r.Counter("c_total", "", "k").Get("a") != 10 {
		t.Fatal("re-registration lost the series")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("type mismatch should panic")
		}
	}()
	r.Gauge("c_total", "", "k")
}

func TestConcurrentIncrements(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("hits_total", "", "w")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				c.Inc([]string{"a", "b"}[i%2])
				_ = r.String()
			}
		}(i)
	}
	wg.Wait()
	if c.Get("a") != 4000 || c.Get("b") != 4000 {
		t.Fatalf("lost increments: a=%v b=%v", c.Get("a"), c.Get("b"))
	}
}

func TestHandlerContentType(t *testing.T) {
	r := NewRegistry()
	r.Gauge("up", "").Set(1)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "up 1\n") {
		t.Fatalf("body %q", rec.Body.String())
	}
}

func TestServeListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := NewRegistry()
	r.Gauge("up", "").Set(1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ServeListener(ctx, ln) }()

	base := "http://" + ln.Addr().String()
	get := func(p string) (int, string) {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/healthz"); code != 200 || body != "ok\n" {
		t.Fatalf("healthz %d %q", code, body)
	}
	if code, body := get("/metrics"); code != 200 || !strings.Contains(body, "up 1") {
		t.Fatalf("metrics %d %q", code, body)
	}
	if code, _ := get("/nope"); code != 404 {
		t.Fatalf("unknown path %d", code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestServeBadListen(t *testing.T) {
	if err := NewRegistry().Serve(context.Background(), "256.256.256.256:99999"); err == nil {
		t.Fatal("expected listen error")
	}
}
