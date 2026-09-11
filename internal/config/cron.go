package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed 5-field cron expression (minute hour day-of-month
// month day-of-week). Supported syntax: `*`, lists `1,2,3`, ranges `1-5`,
// steps `*/15` and `1-30/5`, month and weekday names, and the @hourly,
// @daily, @midnight, @weekly, @monthly, @yearly, @annually shortcuts.
// Day-of-month and day-of-week follow Vixie cron: when both are
// restricted, either may match.
type Schedule struct {
	minute, hour, dom, month, dow uint64 // bitmasks
	domAny, dowAny                bool
	expr                          string
}

var (
	monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
	dowNames   = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
	shortcuts  = map[string]string{
		"@hourly":   "0 * * * *",
		"@daily":    "0 0 * * *",
		"@midnight": "0 0 * * *",
		"@weekly":   "0 0 * * 0",
		"@monthly":  "0 0 1 * *",
		"@yearly":   "0 0 1 1 *",
		"@annually": "0 0 1 1 *",
	}
)

// ParseCron parses expr.
func ParseCron(expr string) (*Schedule, error) {
	orig := expr
	expr = strings.TrimSpace(expr)
	if s, ok := shortcuts[strings.ToLower(expr)]; ok {
		expr = s
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron %q: want 5 fields (minute hour dom month dow), got %d", orig, len(fields))
	}
	s := &Schedule{expr: orig}
	var err error
	if s.minute, _, err = parseField(fields[0], 0, 59, nil); err != nil {
		return nil, fmt.Errorf("cron %q: minute: %w", orig, err)
	}
	if s.hour, _, err = parseField(fields[1], 0, 23, nil); err != nil {
		return nil, fmt.Errorf("cron %q: hour: %w", orig, err)
	}
	if s.dom, s.domAny, err = parseField(fields[2], 1, 31, nil); err != nil {
		return nil, fmt.Errorf("cron %q: day-of-month: %w", orig, err)
	}
	if s.month, _, err = parseField(fields[3], 1, 12, monthNames); err != nil {
		return nil, fmt.Errorf("cron %q: month: %w", orig, err)
	}
	if s.dow, s.dowAny, err = parseField(fields[4], 0, 7, dowNames); err != nil {
		return nil, fmt.Errorf("cron %q: day-of-week: %w", orig, err)
	}
	if s.dow&(1<<7) != 0 { // 7 is an alias for Sunday
		s.dow |= 1
		s.dow &^= 1 << 7
	}
	return s, nil
}

// parseField returns the bitmask for one field and whether it was a bare
// `*` (needed for the dom/dow OR rule).
func parseField(f string, lo, hi int, names map[string]int) (uint64, bool, error) {
	var mask uint64
	star := false
	for _, part := range strings.Split(f, ",") {
		if part == "" {
			return 0, false, errors.New("empty list item")
		}
		step := 1
		rng := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 {
				return 0, false, fmt.Errorf("bad step in %q", part)
			}
			step = n
			rng = part[:i]
		}
		start, end := lo, hi
		switch {
		case rng == "*":
			if step == 1 && len(f) == 1 {
				star = true
			}
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if start, err = parseValue(a, lo, hi, names); err != nil {
				return 0, false, err
			}
			if end, err = parseValue(b, lo, hi, names); err != nil {
				return 0, false, err
			}
			if start > end {
				return 0, false, fmt.Errorf("range %q is reversed", rng)
			}
		default:
			v, err := parseValue(rng, lo, hi, names)
			if err != nil {
				return 0, false, err
			}
			start = v
			if step == 1 {
				end = v
			} // "5/10" means every 10 starting at 5, as in Vixie cron
		}
		for v := start; v <= end; v += step {
			mask |= 1 << uint(v)
		}
	}
	return mask, star, nil
}

func parseValue(s string, lo, hi int, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("bad value %q", s)
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("value %d out of range %d-%d", v, lo, hi)
	}
	return v, nil
}

// Matches reports whether t (to the minute) satisfies the schedule.
func (s *Schedule) Matches(t time.Time) bool {
	if s.minute&(1<<uint(t.Minute())) == 0 || s.hour&(1<<uint(t.Hour())) == 0 || s.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domOK := s.dom&(1<<uint(t.Day())) != 0
	dowOK := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domAny && s.dowAny:
		return true
	case s.domAny:
		return dowOK
	case s.dowAny:
		return domOK
	default:
		return domOK || dowOK
	}
}

// Prev finds the most recent matching minute at or before t, scanning back
// no further than lookback (a window longer than its own recurrence gap
// would overlap itself, so callers pass the window duration). It walks
// minute by minute, which is fine for lookbacks up to a few days.
func (s *Schedule) Prev(t time.Time, lookback time.Duration) (time.Time, bool) {
	cur := t.Truncate(time.Minute)
	if cur.After(t) { // Truncate on a non-UTC location can land in the future across DST edges
		cur = cur.Add(-time.Minute)
	}
	limit := t.Add(-lookback)
	for !cur.Before(limit) {
		if s.Matches(cur) {
			return cur, true
		}
		cur = cur.Add(-time.Minute)
	}
	return time.Time{}, false
}

// Next finds the first matching minute strictly after t within horizon.
func (s *Schedule) Next(t time.Time, horizon time.Duration) (time.Time, bool) {
	cur := t.Truncate(time.Minute).Add(time.Minute)
	limit := t.Add(horizon)
	for !cur.After(limit) {
		if s.Matches(cur) {
			return cur, true
		}
		cur = cur.Add(time.Minute)
	}
	return time.Time{}, false
}

// String returns the original expression.
func (s *Schedule) String() string { return s.expr }
