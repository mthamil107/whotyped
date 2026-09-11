package config

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseCronErrors(t *testing.T) {
	bad := []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8",
		"*/0 * * * *", "5-1 * * * *", "a * * * *", "1,,2 * * * *", "* * * * mon-xyz"}
	for _, e := range bad {
		if _, err := ParseCron(e); err == nil {
			t.Errorf("ParseCron(%q) accepted", e)
		}
	}
}

func TestCronMatches(t *testing.T) {
	cases := []struct {
		expr string
		at   string
		want bool
	}{
		{"* * * * *", "2026-09-11T14:03:00Z", true},
		{"0 17 * * 5", "2026-09-11T17:00:00Z", true}, // 2026-09-11 is a Friday
		{"0 17 * * fri", "2026-09-11T17:00:00Z", true},
		{"0 17 * * FRI", "2026-09-11T17:00:00Z", true},
		{"0 17 * * 5", "2026-09-11T17:01:00Z", false},
		{"0 17 * * 4", "2026-09-11T17:00:00Z", false},
		{"*/15 * * * *", "2026-09-11T14:45:00Z", true},
		{"*/15 * * * *", "2026-09-11T14:50:00Z", false},
		{"0 9-17 * * 1-5", "2026-09-11T12:00:00Z", true},
		{"0 9-17 * * 1-5", "2026-09-12T12:00:00Z", false}, // Saturday
		{"0 9-17/4 * * *", "2026-09-11T13:00:00Z", true},
		{"0 9-17/4 * * *", "2026-09-11T14:00:00Z", false},
		{"30 2 1 * *", "2026-10-01T02:30:00Z", true},
		{"30 2 1 * *", "2026-10-02T02:30:00Z", false},
		{"0 0 * jan,dec *", "2026-12-25T00:00:00Z", true},
		{"0 0 * jan,dec *", "2026-11-25T00:00:00Z", false},
		{"0 0 * * 7", "2026-09-13T00:00:00Z", true}, // 7 == Sunday
		{"0 0 * * 0", "2026-09-13T00:00:00Z", true},
		// Vixie rule: dom OR dow when both restricted.
		{"0 0 13 * 5", "2026-09-13T00:00:00Z", true}, // matches dom 13 (a Sunday)
		{"0 0 13 * 5", "2026-09-11T00:00:00Z", true}, // matches dow Friday
		{"0 0 13 * 5", "2026-09-12T00:00:00Z", false},
		{"@hourly", "2026-09-11T14:00:00Z", true},
		{"@hourly", "2026-09-11T14:01:00Z", false},
		{"@weekly", "2026-09-13T00:00:00Z", true},
		{"5/10 * * * *", "2026-09-11T14:25:00Z", true},
		{"5/10 * * * *", "2026-09-11T14:20:00Z", false},
	}
	for _, c := range cases {
		s, err := ParseCron(c.expr)
		if err != nil {
			t.Errorf("ParseCron(%q): %v", c.expr, err)
			continue
		}
		if got := s.Matches(at(c.at)); got != c.want {
			t.Errorf("%q at %s = %v, want %v", c.expr, c.at, got, c.want)
		}
	}
}

func TestCronPrevNext(t *testing.T) {
	s, _ := ParseCron("0 17 * * 5")
	now := at("2026-09-11T18:30:00Z")
	prev, ok := s.Prev(now, 4*time.Hour)
	if !ok || !prev.Equal(at("2026-09-11T17:00:00Z")) {
		t.Errorf("Prev = %v %v", prev, ok)
	}
	if _, ok := s.Prev(now, time.Hour); ok {
		t.Error("Prev found a start outside the lookback")
	}
	next, ok := s.Next(now, 8*24*time.Hour)
	if !ok || !next.Equal(at("2026-09-18T17:00:00Z")) {
		t.Errorf("Next = %v %v", next, ok)
	}
	// A time exactly on the boundary is its own Prev.
	prev, ok = s.Prev(at("2026-09-11T17:00:30Z"), time.Minute)
	if !ok || !prev.Equal(at("2026-09-11T17:00:00Z")) {
		t.Errorf("Prev on boundary = %v %v", prev, ok)
	}
}

func TestFreezeWindowActive(t *testing.T) {
	cron := FreezeWindow{Name: "weekend", Cron: "0 17 * * 5", Duration: Duration(63 * time.Hour)} // Fri 17:00 -> Mon 08:00
	cases := []struct {
		at   string
		want bool
	}{
		{"2026-09-11T16:59:00Z", false},
		{"2026-09-11T17:00:00Z", true},
		{"2026-09-12T12:00:00Z", true},
		{"2026-09-14T07:59:59Z", true},
		{"2026-09-14T08:00:00Z", false},
		{"2026-09-15T12:00:00Z", false},
	}
	for _, c := range cases {
		if got := cron.Active(at(c.at)); got != c.want {
			t.Errorf("cron window at %s = %v, want %v", c.at, got, c.want)
		}
	}
	oneOff := FreezeWindow{Name: "release", Start: Time{at("2026-09-20T00:00:00Z")}, End: Time{at("2026-09-21T00:00:00Z")}}
	if oneOff.Active(at("2026-09-19T23:59:59Z")) || !oneOff.Active(at("2026-09-20T00:00:00Z")) || oneOff.Active(at("2026-09-21T00:00:00Z")) {
		t.Error("one-off window bounds wrong")
	}
	cfg := Default()
	cfg.FreezeWindows = []FreezeWindow{oneOff, cron}
	if w := cfg.ActiveFreeze(at("2026-09-12T12:00:00Z")); w == nil || w.Name != "weekend" {
		t.Errorf("ActiveFreeze = %+v", w)
	}
	if w := cfg.ActiveFreeze(at("2026-09-16T12:00:00Z")); w != nil {
		t.Errorf("ActiveFreeze outside windows = %+v", w)
	}
}

func TestFreezeWindowTimezone(t *testing.T) {
	if _, err := time.LoadLocation("America/New_York"); err != nil {
		t.Skip("tzdata not available:", err)
	}
	w := FreezeWindow{Name: "ny", Cron: "0 17 * * 5", Duration: Duration(2 * time.Hour), Timezone: "America/New_York"}
	// 17:30 New York on Friday 2026-09-11 is 21:30 UTC (EDT).
	if !w.Active(at("2026-09-11T21:30:00Z")) {
		t.Error("window should be active at 17:30 New York")
	}
	if w.Active(at("2026-09-11T17:30:00Z")) {
		t.Error("window should not be active at 17:30 UTC (13:30 New York)")
	}
}
