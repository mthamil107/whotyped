package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
)

var base = time.Date(2026, 9, 7, 9, 0, 0, 0, time.UTC)

// writeFixture writes 10 sessions across 3 classes: 4 suspected (two of them
// escalating info -> alert -> high), 3 declared, 3 human info-level blips,
// plus one freeze violation. Session 3 lives in a rotated sibling.
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")
	mk := func(i int, ts time.Time, ev string, class score.Class, sc int, lvl score.Level, reasons ...string) alert.Alert {
		var rs []clues.Clue
		for _, r := range reasons {
			rs = append(rs, clues.Clue{ID: r, Category: clues.Category(strings.SplitN(r, ".", 2)[0]), Weight: 10, Evidence: "e"})
		}
		a := alert.Alert{Schema: alert.Schema, TS: ts, Host: "web-0" + string(rune('1'+i%2)), Event: ev, Class: class,
			Mode: "remote_agent", User: "user" + string(rune('a'+i%4)), SrcIP: "10.0.0." + string(rune('1'+i%3)),
			KeyFingerprint: "SHA256:k" + string(rune('A'+i%3)), Score: sc, Level: lvl, Reasons: rs,
			Suppressed: []score.Suppression{}, SessionID: "tr_" + strings.Repeat(string(rune('a'+i)), 12), Connections: 1,
			ActionsHint: "hint"}
		if class == score.ClassDeclared {
			a.Agent = "claude-code"
		} else if class == score.ClassSuspected {
			a.Agent = "?claude-code"
		}
		if ev == alert.EvFreeze {
			a.FreezeWindow = &alert.Freeze{Name: "weekend", Until: ts.Add(time.Hour)}
		}
		return a
	}
	var main, rotated []alert.Alert
	for i := 0; i < 10; i++ {
		ts := base.Add(time.Duration(i) * time.Hour)
		var as []alert.Alert
		switch {
		case i < 4: // suspected
			as = append(as, mk(i, ts, alert.EvDetected, score.ClassSuspected, 72, score.LevelAlert, "rhythm.burst", "pty.none", "style.tool_wrapper"))
			if i < 2 {
				as = append(as, mk(i, ts.Add(5*time.Minute), alert.EvHigh, score.ClassSuspected, 91, score.LevelHigh, "rhythm.burst", "pty.none", "style.heredoc"))
				as = append(as, mk(i, ts.Add(20*time.Minute), alert.EvEnded, score.ClassSuspected, 91, score.LevelHigh))
			}
		case i < 7: // declared
			as = append(as, mk(i, ts, alert.EvDeclared, score.ClassDeclared, 20, score.LevelInfo, "env.ai_agent"))
			if i == 6 {
				as = append(as, mk(i, ts.Add(time.Minute), alert.EvFreeze, score.ClassDeclared, 20, score.LevelHigh, "env.ai_agent"))
			}
		default: // human blips
			as = append(as, mk(i, ts, alert.EvDetected, score.ClassHuman, 45, score.LevelInfo, "rhythm.burst"))
		}
		if i == 3 {
			rotated = append(rotated, as...)
		} else {
			main = append(main, as...)
		}
	}
	write := func(p string, as []alert.Alert) {
		var buf bytes.Buffer
		for _, a := range as {
			b, _ := json.Marshal(a)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(path, main)
	write(path+".1", rotated)
	return path
}

func TestAggregateTotals(t *testing.T) {
	path := writeFixture(t)
	var out bytes.Buffer
	code, err := Run(Options{AlertsPath: path, Format: "json", Out: &out})
	if err != nil || code != ExitOK {
		t.Fatalf("code %d err %v", code, err)
	}
	var sum Summary
	if err := json.Unmarshal(out.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Totals.Sessions != 10 {
		t.Fatalf("sessions %d, want 10 (rotated file must be included)", sum.Totals.Sessions)
	}
	if sum.Totals.ByClass["suspected_agent"] != 4 || sum.Totals.ByClass["declared_agent"] != 3 || sum.Totals.ByClass["human"] != 3 {
		t.Fatalf("by class %v", sum.Totals.ByClass)
	}
	if sum.Totals.FreezeViolations != 1 || sum.Totals.Alerts != 15 {
		t.Fatalf("freeze %d alerts %d", sum.Totals.FreezeViolations, sum.Totals.Alerts)
	}
	if sum.Totals.AlertsByLevel["high"] != 5 { // 2 high + 2 ended(high) + 1 freeze
		t.Fatalf("levels %v", sum.Totals.AlertsByLevel)
	}
	// Session 0 escalated: max score/level kept, first and last TS spanned.
	var s0 Session
	for _, s := range sum.Sessions {
		if s.SessionID == "tr_aaaaaaaaaaaa" {
			s0 = s
		}
	}
	if s0.MaxScore != 91 || s0.MaxLevel != score.LevelHigh || s0.Alerts != 3 || s0.Last.Sub(s0.First) != 20*time.Minute || s0.LastEvent != alert.EvEnded {
		t.Fatalf("session 0 row %+v", s0)
	}
	if len(s0.Clues) != 4 { // burst, pty.none, tool_wrapper, heredoc
		t.Fatalf("clues %v", s0.Clues)
	}
	if sum.By != "account" || len(sum.Top) != 4 || sum.Top[0].Sessions != 3 {
		t.Fatalf("top %+v", sum.Top)
	}
	if sum.TopClues[0].Clue != "rhythm.burst" || sum.TopClues[0].Sessions != 7 {
		t.Fatalf("top clues %+v", sum.TopClues)
	}
	found := false
	for _, a := range sum.Agents {
		if a.Key == "claude-code" && a.Declared == 3 && a.Sessions == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("agents %+v", sum.Agents)
	}
}

func TestFormatsAndDimensions(t *testing.T) {
	path := writeFixture(t)
	for _, by := range []string{"account", "server", "agent", "key"} {
		for _, format := range []string{"table", "md"} {
			var out bytes.Buffer
			code, err := Run(Options{AlertsPath: path, By: by, Format: format, Out: &out})
			if err != nil || code != ExitOK {
				t.Fatalf("%s/%s: code %d err %v", by, format, code, err)
			}
			if low := strings.ToLower(out.String()); !strings.Contains(low, "freeze") || !strings.Contains(low, by) {
				t.Fatalf("%s/%s output:\n%s", by, format, out.String())
			}
		}
	}
	var out bytes.Buffer
	if code, err := Run(Options{AlertsPath: path, By: "colour", Out: &out}); err == nil || code != ExitError {
		t.Fatal("bad --by must be an error")
	}
	// MinLevel high leaves only the escalated and freeze sessions.
	out.Reset()
	Run(Options{AlertsPath: path, Format: "json", MinLevel: "high", Out: &out})
	var sum Summary
	json.Unmarshal(out.Bytes(), &sum)
	if sum.Totals.Sessions != 3 {
		t.Fatalf("min level high: %d sessions", sum.Totals.Sessions)
	}
	// Since/Until window.
	out.Reset()
	Run(Options{AlertsPath: path, Format: "json", Since: base.Add(7 * time.Hour), Until: base.Add(8 * time.Hour), Out: &out})
	json.Unmarshal(out.Bytes(), &sum)
	if sum.Totals.Sessions != 2 {
		t.Fatalf("window: %d sessions", sum.Totals.Sessions)
	}
}

func TestSessionTimelineAndEmpty(t *testing.T) {
	path := writeFixture(t)
	var out bytes.Buffer
	code, err := Run(Options{AlertsPath: path, Session: "tr_bbbbbbbbbbbb", Out: &out})
	if err != nil || code != ExitOK {
		t.Fatalf("code %d err %v", code, err)
	}
	s := out.String()
	if strings.Count(s, "agent_") != 3 || !strings.Contains(s, "style.heredoc") {
		t.Fatalf("timeline:\n%s", s)
	}
	out.Reset()
	if code, _ := Run(Options{AlertsPath: path, Session: "tr_nope", Out: &out}); code != ExitNoAlerts {
		t.Fatalf("missing session code %d", code)
	}
	out.Reset()
	code, err = Run(Options{AlertsPath: filepath.Join(t.TempDir(), "none.jsonl"), Out: &out})
	if err != nil || code != ExitNoAlerts {
		t.Fatalf("empty: code %d err %v", code, err)
	}
}
