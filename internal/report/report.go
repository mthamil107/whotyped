// Package report implements `whotyped report`: it reads alerts.jsonl (and its
// rotated siblings), folds the alerts into one row per session, and prints
// totals, a top-N by account / server / agent / key, the most frequent clues
// and a per-agent breakdown, as a table, Markdown or JSON.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/score"
	"github.com/whotyped/whotyped/internal/sinks/jsonfile"
)

// Exit codes: 0 report produced, 1 no alerts in range, 2 error.
const (
	ExitOK       = 0
	ExitNoAlerts = 1
	ExitError    = 2
)

// Options controls Run.
type Options struct {
	AlertsPath string
	Since      time.Time // zero = everything
	Until      time.Time // zero = now
	By         string    // account | server | agent | key (default account)
	Format     string    // table | json | md (default table)
	Session    string    // print the timeline of one session instead of the summary
	MinLevel   string    // info | alert | high; alerts below it are ignored
	Top        int       // rows in the top list; default 10
	Out        io.Writer // default os.Stdout
}

// Session is one deduplicated row per session_id.
type Session struct {
	SessionID  string      `json:"session_id"`
	Host       string      `json:"host"`
	User       string      `json:"user"`
	SrcIP      string      `json:"src_ip"`
	Key        string      `json:"key_fingerprint,omitempty"`
	Agent      string      `json:"agent,omitempty"`
	Class      score.Class `json:"class"`
	Mode       string      `json:"mode"`
	MaxScore   int         `json:"max_score"`
	MaxLevel   score.Level `json:"max_level"`
	First      time.Time   `json:"first"`
	Last       time.Time   `json:"last"`
	Alerts     int         `json:"alerts"`
	Freeze     bool        `json:"freeze_violation"`
	Clues      []string    `json:"clues"`
	LastEvent  string      `json:"last_event"`
	Connection int         `json:"connections"`
}

// Dim is one row of the top-N table.
type Dim struct {
	Key       string  `json:"key"`
	Sessions  int     `json:"sessions"`
	Declared  int     `json:"declared"`
	Suspected int     `json:"suspected"`
	MeanScore float64 `json:"mean_score"`
	MaxScore  int     `json:"max_score"`
}

// ClueCount is a clue id with the number of sessions it appeared in.
type ClueCount struct {
	Clue     string `json:"clue"`
	Sessions int    `json:"sessions"`
}

// Summary is the JSON output and the source of the table / md renderings.
type Summary struct {
	AlertsPath string    `json:"alerts_path"`
	Since      time.Time `json:"since"`
	Until      time.Time `json:"until"`
	By         string    `json:"by"`
	Totals     struct {
		Alerts           int            `json:"alerts"`
		Sessions         int            `json:"sessions"`
		ByClass          map[string]int `json:"sessions_by_class"`
		AlertsByLevel    map[string]int `json:"alerts_by_level"`
		FreezeViolations int            `json:"freeze_violations"`
	} `json:"totals"`
	Top      []Dim       `json:"top"`
	TopClues []ClueCount `json:"top_clues"`
	Agents   []Dim       `json:"agents"`
	Sessions []Session   `json:"sessions"`
}

// Run reads, aggregates and renders. The error is also written to Out's
// stderr counterpart by the caller; it is returned for tests.
func Run(opts Options) (int, error) {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.By == "" {
		opts.By = "account"
	}
	if opts.Format == "" {
		opts.Format = "table"
	}
	if opts.Top <= 0 {
		opts.Top = 10
	}
	switch opts.By {
	case "account", "server", "agent", "key":
	default:
		return ExitError, fmt.Errorf("--by %q: want account, server, agent or key", opts.By)
	}
	switch opts.Format {
	case "table", "json", "md":
	default:
		return ExitError, fmt.Errorf("--format %q: want table, json or md", opts.Format)
	}
	if opts.AlertsPath == "" {
		return ExitError, errors.New("alerts path is required")
	}
	alerts, err := jsonfile.ReadAll(opts.AlertsPath, opts.Since)
	if err != nil {
		return ExitError, err
	}
	alerts = filter(alerts, opts)

	if opts.Session != "" {
		var mine []alert.Alert
		for _, a := range alerts {
			if a.SessionID == opts.Session {
				mine = append(mine, a)
			}
		}
		if len(mine) == 0 {
			fmt.Fprintf(opts.Out, "no alerts for session %s in %s\n", opts.Session, opts.AlertsPath)
			return ExitNoAlerts, nil
		}
		return ExitOK, renderTimeline(opts, mine)
	}

	sum := Aggregate(alerts, opts)
	var renderErr error
	switch opts.Format {
	case "json":
		enc := json.NewEncoder(opts.Out)
		enc.SetIndent("", "  ")
		renderErr = enc.Encode(sum)
	case "md":
		renderMarkdown(opts.Out, sum)
	default:
		renderTable(opts.Out, sum)
	}
	if renderErr != nil {
		return ExitError, renderErr
	}
	if len(alerts) == 0 {
		return ExitNoAlerts, nil
	}
	return ExitOK, nil
}

func filter(in []alert.Alert, opts Options) []alert.Alert {
	min := score.ParseLevel(opts.MinLevel)
	out := in[:0]
	for _, a := range in {
		if !opts.Until.IsZero() && a.TS.After(opts.Until) {
			continue
		}
		if a.Level.Rank() < min.Rank() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// Aggregate folds alerts into the Summary.
func Aggregate(alerts []alert.Alert, opts Options) Summary {
	var sum Summary
	sum.AlertsPath = opts.AlertsPath
	sum.Since, sum.Until, sum.By = opts.Since, opts.Until, opts.By
	sum.Totals.ByClass = map[string]int{}
	sum.Totals.AlertsByLevel = map[string]int{}
	sum.Totals.Alerts = len(alerts)

	sessions := map[string]*Session{}
	clueSets := map[string]map[string]bool{}
	for _, a := range alerts {
		sum.Totals.AlertsByLevel[string(a.Level)]++
		if a.Event == alert.EvFreeze {
			sum.Totals.FreezeViolations++
		}
		s := sessions[a.SessionID]
		if s == nil {
			s = &Session{SessionID: a.SessionID, Host: a.Host, User: a.User, SrcIP: a.SrcIP, Key: a.KeyFingerprint,
				Mode: a.Mode, First: a.TS, Last: a.TS, MaxScore: -1, Class: a.Class}
			sessions[a.SessionID] = s
			clueSets[a.SessionID] = map[string]bool{}
		}
		s.Alerts++
		if a.TS.Before(s.First) {
			s.First = a.TS
		}
		if !a.TS.Before(s.Last) {
			s.Last = a.TS
			s.LastEvent = a.Event
		}
		if a.Score > s.MaxScore {
			s.MaxScore = a.Score
			s.Mode = a.Mode
		}
		if a.Level.Rank() > s.MaxLevel.Rank() {
			s.MaxLevel = a.Level
		}
		if a.Connections > s.Connection {
			s.Connection = a.Connections
		}
		// A declaration wins over any inference; otherwise suspected beats human.
		if a.Class == score.ClassDeclared || (a.Class == score.ClassSuspected && s.Class != score.ClassDeclared) {
			s.Class = a.Class
		}
		if a.Agent != "" && (s.Agent == "" || !strings.HasPrefix(a.Agent, "?")) {
			s.Agent = a.Agent
		}
		if a.Event == alert.EvFreeze {
			s.Freeze = true
		}
		for _, r := range a.Reasons {
			if r.Weight > 0 {
				clueSets[a.SessionID][r.ID] = true
			}
		}
	}

	for id, s := range sessions {
		for c := range clueSets[id] {
			s.Clues = append(s.Clues, c)
		}
		sort.Strings(s.Clues)
		sum.Totals.ByClass[string(s.Class)]++
		sum.Sessions = append(sum.Sessions, *s)
	}
	sort.Slice(sum.Sessions, func(i, j int) bool {
		if sum.Sessions[i].MaxScore != sum.Sessions[j].MaxScore {
			return sum.Sessions[i].MaxScore > sum.Sessions[j].MaxScore
		}
		return sum.Sessions[i].First.Before(sum.Sessions[j].First)
	})
	sum.Totals.Sessions = len(sum.Sessions)

	sum.Top = topBy(sum.Sessions, dimKey(opts.By), opts.Top)
	sum.Agents = topBy(sum.Sessions, dimKey("agent"), 0)

	clueCount := map[string]int{}
	for _, s := range sum.Sessions {
		for _, c := range s.Clues {
			clueCount[c]++
		}
	}
	for c, n := range clueCount {
		sum.TopClues = append(sum.TopClues, ClueCount{c, n})
	}
	sort.Slice(sum.TopClues, func(i, j int) bool {
		if sum.TopClues[i].Sessions != sum.TopClues[j].Sessions {
			return sum.TopClues[i].Sessions > sum.TopClues[j].Sessions
		}
		return sum.TopClues[i].Clue < sum.TopClues[j].Clue
	})
	if len(sum.TopClues) > 5 {
		sum.TopClues = sum.TopClues[:5]
	}
	return sum
}

func dimKey(by string) func(Session) string {
	switch by {
	case "server":
		return func(s Session) string { return orDash(s.Host) }
	case "agent":
		return func(s Session) string {
			switch {
			case s.Agent == "":
				return "-"
			case strings.HasPrefix(s.Agent, "?"):
				return s.Agent[1:] + " (guessed)"
			}
			return s.Agent
		}
	case "key":
		return func(s Session) string { return orDash(s.Key) }
	default:
		return func(s Session) string { return orDash(s.User) }
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// topBy groups sessions by key; limit 0 means all rows.
func topBy(sessions []Session, key func(Session) string, limit int) []Dim {
	acc := map[string]*Dim{}
	total := map[string]int{}
	for _, s := range sessions {
		k := key(s)
		d := acc[k]
		if d == nil {
			d = &Dim{Key: k}
			acc[k] = d
		}
		d.Sessions++
		total[k] += s.MaxScore
		if s.MaxScore > d.MaxScore {
			d.MaxScore = s.MaxScore
		}
		switch s.Class {
		case score.ClassDeclared:
			d.Declared++
		case score.ClassSuspected:
			d.Suspected++
		}
	}
	out := make([]Dim, 0, len(acc))
	for k, d := range acc {
		d.MeanScore = math.Round(float64(total[k])/float64(d.Sessions)*10) / 10
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sessions != out[j].Sessions {
			return out[i].Sessions > out[j].Sessions
		}
		if out[i].MaxScore != out[j].MaxScore {
			return out[i].MaxScore > out[j].MaxScore
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ---------------------------------------------------------------------------
// rendering

func rangeLine(sum Summary) string {
	since := "beginning"
	if !sum.Since.IsZero() {
		since = sum.Since.UTC().Format(time.RFC3339)
	}
	until := "now"
	if !sum.Until.IsZero() {
		until = sum.Until.UTC().Format(time.RFC3339)
	}
	return since + " .. " + until
}

func classTotals(m map[string]int) string {
	return fmt.Sprintf("human %d, declared_agent %d, suspected_agent %d", m["human"], m["declared_agent"], m["suspected_agent"])
}

func levelTotals(m map[string]int) string {
	return fmt.Sprintf("info %d, alert %d, high %d", m["info"], m["alert"], m["high"])
}

func renderTable(w io.Writer, sum Summary) {
	fmt.Fprintf(w, "whotyped report: %s (%s)\n\n", sum.AlertsPath, rangeLine(sum))
	fmt.Fprintf(w, "alerts   %d\n", sum.Totals.Alerts)
	fmt.Fprintf(w, "sessions %d (%s)\n", sum.Totals.Sessions, classTotals(sum.Totals.ByClass))
	fmt.Fprintf(w, "levels   %s\n", levelTotals(sum.Totals.AlertsByLevel))
	fmt.Fprintf(w, "freeze violations %d\n\n", sum.Totals.FreezeViolations)

	fmt.Fprintf(w, "top %d by %s\n", len(sum.Top), sum.By)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  "+strings.ToUpper(sum.By)+"\tSESSIONS\tDECLARED\tSUSPECTED\tMEAN\tMAX")
	for _, d := range sum.Top {
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%.1f\t%d\n", d.Key, d.Sessions, d.Declared, d.Suspected, d.MeanScore, d.MaxScore)
	}
	tw.Flush()

	fmt.Fprintln(w, "\ntop clues")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  CLUE\tSESSIONS")
	for _, c := range sum.TopClues {
		fmt.Fprintf(tw, "  %s\t%d\n", c.Clue, c.Sessions)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nagents")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  AGENT\tSESSIONS\tDECLARED\tSUSPECTED\tMEAN\tMAX")
	for _, d := range sum.Agents {
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%.1f\t%d\n", d.Key, d.Sessions, d.Declared, d.Suspected, d.MeanScore, d.MaxScore)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nsessions")
	tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  SESSION\tUSER\tSRC\tCLASS\tMAX\tLEVEL\tFIRST\tLAST\tALERTS\tAGENT")
	for _, s := range sum.Sessions {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\n", s.SessionID, s.User, s.SrcIP, s.Class, s.MaxScore, s.MaxLevel,
			s.First.UTC().Format("01-02 15:04"), s.Last.UTC().Format("01-02 15:04"), s.Alerts, orDash(s.Agent))
	}
	tw.Flush()
}

func renderMarkdown(w io.Writer, sum Summary) {
	fmt.Fprintf(w, "## whotyped weekly report\n\n")
	fmt.Fprintf(w, "Source: `%s`, range %s.\n\n", sum.AlertsPath, rangeLine(sum))
	fmt.Fprintf(w, "- Alerts: **%d** (%s)\n", sum.Totals.Alerts, levelTotals(sum.Totals.AlertsByLevel))
	fmt.Fprintf(w, "- Sessions: **%d** (%s)\n", sum.Totals.Sessions, classTotals(sum.Totals.ByClass))
	fmt.Fprintf(w, "- Freeze violations: **%d**\n\n", sum.Totals.FreezeViolations)

	fmt.Fprintf(w, "### Top by %s\n\n", sum.By)
	fmt.Fprintf(w, "| %s | Sessions | Declared | Suspected | Mean score | Max score |\n|---|---:|---:|---:|---:|---:|\n", sum.By)
	for _, d := range sum.Top {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %.1f | %d |\n", mdEscape(d.Key), d.Sessions, d.Declared, d.Suspected, d.MeanScore, d.MaxScore)
	}
	fmt.Fprintf(w, "\n### Top clues\n\n| Clue | Sessions |\n|---|---:|\n")
	for _, c := range sum.TopClues {
		fmt.Fprintf(w, "| `%s` | %d |\n", c.Clue, c.Sessions)
	}
	fmt.Fprintf(w, "\n### Agents\n\n| Agent | Sessions | Declared | Suspected | Mean score | Max score |\n|---|---:|---:|---:|---:|---:|\n")
	for _, d := range sum.Agents {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %.1f | %d |\n", mdEscape(d.Key), d.Sessions, d.Declared, d.Suspected, d.MeanScore, d.MaxScore)
	}
	fmt.Fprintf(w, "\n### Sessions\n\n| Session | User | Source | Class | Max | Level | First (UTC) | Last (UTC) | Alerts |\n|---|---|---|---|---:|---|---|---|---:|\n")
	for _, s := range sum.Sessions {
		fmt.Fprintf(w, "| `%s` | %s | %s | %s | %d | %s | %s | %s | %d |\n", s.SessionID, mdEscape(s.User), s.SrcIP, s.Class, s.MaxScore, s.MaxLevel,
			s.First.UTC().Format("2006-01-02 15:04"), s.Last.UTC().Format("2006-01-02 15:04"), s.Alerts)
	}
	fmt.Fprintln(w)
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "`", "'").Replace(s)
}

// renderTimeline prints every alert of one session in order, with reasons.
func renderTimeline(opts Options, alerts []alert.Alert) error {
	w := opts.Out
	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].TS.Before(alerts[j].TS) })
	if opts.Format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(alerts)
	}
	first := alerts[0]
	md := opts.Format == "md"
	if md {
		fmt.Fprintf(w, "### Session `%s`\n\n%s from %s on %s, %d alert(s)\n\n", first.SessionID, first.User, first.SrcIP, first.Host, len(alerts))
	} else {
		fmt.Fprintf(w, "session %s: %s from %s on %s, %d alert(s)\n\n", first.SessionID, first.User, first.SrcIP, first.Host, len(alerts))
	}
	for _, a := range alerts {
		agent := a.Agent
		if agent == "" {
			agent = "-"
		}
		if md {
			fmt.Fprintf(w, "**%s** `%s` score %d level %s class %s mode %s agent %s\n\n", a.TS.UTC().Format(time.RFC3339), a.Event, a.Score, a.Level, a.Class, a.Mode, agent)
			if len(a.Reasons) > 0 {
				fmt.Fprintf(w, "| Clue | Weight | Evidence |\n|---|---:|---|\n")
				for _, r := range a.Reasons {
					fmt.Fprintf(w, "| `%s` | %+d | %s |\n", r.ID, r.Weight, mdEscape(r.Evidence))
				}
				fmt.Fprintln(w)
			}
			continue
		}
		fmt.Fprintf(w, "%s  %-18s score %3d  level %-5s class %s mode %s agent %s\n", a.TS.UTC().Format(time.RFC3339), a.Event, a.Score, a.Level, a.Class, a.Mode, agent)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, r := range a.Reasons {
			fmt.Fprintf(tw, "    %s\t%+d\t%s\n", r.ID, r.Weight, r.Evidence)
		}
		for _, s := range a.Suppressed {
			fmt.Fprintf(tw, "    suppressed %s\t%+d\tby profile %s\n", s.Clue, s.Weight, s.Profile)
		}
		tw.Flush()
		if a.FreezeWindow != nil {
			fmt.Fprintf(w, "    freeze window %s until %s\n", a.FreezeWindow.Name, a.FreezeWindow.Until.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(w, "    %s\n\n", a.ActionsHint)
	}
	return nil
}
