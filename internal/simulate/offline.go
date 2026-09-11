// Package simulate implements `whotyped simulate`: the offline mode replays a
// labelled scenario through the real correlator and scorer with the embedded
// rule pack; the online mode drives the system ssh client against a host
// running whotyped and waits for the alert.
package simulate

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/event"
	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/score"
	"github.com/whotyped/whotyped/internal/session"
)

// Scenarios are byte-identical copies of testdata/dataset/*; Go's embed
// cannot reach a parent directory and scenarios_sync_test.go keeps them in
// step.
//
//go:embed scenarios
var Scenarios embed.FS

// Exit codes shared by both modes (ARCHITECTURE.md section 7).
const (
	ExitMatch    = 0 // offline: verdict matches expected.json; online: alert >= alert threshold
	ExitMismatch = 1 // offline: verdict differs; online: an alert arrived but below the threshold
	ExitTimeout  = 2 // online: no alert before --timeout; offline: unknown scenario
	ExitSSH      = 3 // online: ssh client missing or the connection failed
)

// aliases map the short names from the design doc to dataset directories.
var aliases = map[string]string{
	"claude-bash":  "claude-bash-over-ssh",
	"paramiko-mcp": "mcp-paramiko",
	"paramiko":     "mcp-paramiko",
	"local-agent":  "local-agent-skip-flags",
	"human":        "human-admin",
	"vscode":       "vscode-remote",
	"declared":     "declared-agent",
}

// Expectation mirrors testdata/dataset/<scenario>/expected.json.
type Expectation struct {
	ScoreMin int         `json:"score_min"`
	ScoreMax int         `json:"score_max"`
	Class    score.Class `json:"class"`
	Level    score.Level `json:"level,omitempty"`
	Mode     string      `json:"mode,omitempty"`
	Notes    string      `json:"notes,omitempty"`
}

// Result is the offline outcome, also emitted as JSON with --json.
type Result struct {
	Scenario string        `json:"scenario"`
	Events   int           `json:"events"`
	Tracks   int           `json:"tracks"`
	Subject  string        `json:"subject"`
	Verdict  score.Verdict `json:"verdict"`
	Expected Expectation   `json:"expected"`
	Pass     bool          `json:"pass"`
	Failures []string      `json:"failures,omitempty"`
}

// Resolve maps a user-supplied scenario name to a dataset directory name.
func Resolve(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if full, ok := aliases[name]; ok {
		return full
	}
	return name
}

// List returns the embedded scenario names in sorted order.
func List() []string {
	entries, err := fs.ReadDir(Scenarios, "scenarios")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Load returns the events and expectation of one embedded scenario.
func Load(name string) (events []event.Event, want Expectation, err error) {
	name = Resolve(name)
	f, err := Scenarios.Open("scenarios/" + name + "/events.jsonl")
	if err != nil {
		return nil, want, fmt.Errorf("unknown scenario %q (try --scenario list)", name)
	}
	defer f.Close()
	events, err = score.ReadEvents(f)
	if err != nil {
		return nil, want, err
	}
	raw, err := fs.ReadFile(Scenarios, "scenarios/"+name+"/expected.json")
	if err != nil {
		return nil, want, err
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		return nil, want, fmt.Errorf("%s/expected.json: %w", name, err)
	}
	return events, want, nil
}

// Evaluate replays the scenario with the embedded rule pack (every profile
// enabled, as the dataset labels assume) and compares against expected.json.
func Evaluate(name string) (Result, error) {
	name = Resolve(name)
	events, want, err := Load(name)
	if err != nil {
		return Result{}, err
	}
	pack, err := rules.Load()
	if err != nil {
		return Result{}, err
	}
	c := session.New(session.Options{})
	verdicts := score.Replay(events, c, score.New(score.DefaultConfig()), pack)
	tracks := c.Tracks()
	if len(tracks) == 0 {
		return Result{}, fmt.Errorf("scenario %s produced no tracks", name)
	}
	// The subject is the busiest track, as in the scorer's dataset test.
	sort.SliceStable(tracks, func(i, j int) bool { return activity(tracks[i]) > activity(tracks[j]) })
	subject := tracks[0]
	v := verdicts[subject.ID]

	res := Result{
		Scenario: name,
		Events:   len(events),
		Tracks:   len(tracks),
		Subject:  fmt.Sprintf("%s@%s (%s)", subject.Key.User, subject.Key.SrcIP, subject.ID),
		Verdict:  v,
		Expected: want,
	}
	if v.Score < want.ScoreMin || v.Score > want.ScoreMax {
		res.Failures = append(res.Failures, fmt.Sprintf("score %d outside %d..%d", v.Score, want.ScoreMin, want.ScoreMax))
	}
	if v.Class != want.Class {
		res.Failures = append(res.Failures, fmt.Sprintf("class %s, want %s", v.Class, want.Class))
	}
	if want.Level != "" && v.Level != want.Level {
		res.Failures = append(res.Failures, fmt.Sprintf("level %s, want %s", v.Level, want.Level))
	}
	if want.Mode != "" && v.Mode != want.Mode {
		res.Failures = append(res.Failures, fmt.Sprintf("mode %s, want %s", v.Mode, want.Mode))
	}
	res.Pass = len(res.Failures) == 0
	return res, nil
}

func activity(t *session.Track) int {
	return len(t.Execs) + len(t.Procs) + len(t.Connections)
}

// RunOffline is the `simulate --offline` entry point. scenario "list" prints
// the available scenarios. Exit 0 when the verdict matches expected.json.
func RunOffline(scenario string, w io.Writer, jsonOut bool) int {
	if scenario == "" {
		scenario = "claude-bash-over-ssh"
	}
	if strings.EqualFold(scenario, "list") {
		return listScenarios(w, jsonOut)
	}
	res, err := Evaluate(scenario)
	if err != nil {
		fmt.Fprintln(w, "simulate:", err)
		return ExitTimeout
	}
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printResult(w, res)
	}
	if res.Pass {
		return ExitMatch
	}
	return ExitMismatch
}

func listScenarios(w io.Writer, jsonOut bool) int {
	type row struct {
		Name     string      `json:"name"`
		Expected Expectation `json:"expected"`
	}
	var rows []row
	for _, name := range List() {
		_, want, err := Load(name)
		if err != nil {
			continue
		}
		rows = append(rows, row{name, want})
	}
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return ExitMatch
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tEXPECTED SCORE\tCLASS\tLEVEL\tNOTES")
	for _, r := range rows {
		level := string(r.Expected.Level)
		if level == "" {
			level = "-"
		}
		fmt.Fprintf(tw, "%s\t%d..%d\t%s\t%s\t%s\n", r.Name, r.Expected.ScoreMin, r.Expected.ScoreMax, r.Expected.Class, level, r.Expected.Notes)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "aliases: claude-bash, paramiko-mcp, local-agent, human, vscode, declared")
	return ExitMatch
}

func printResult(w io.Writer, res Result) {
	v := res.Verdict
	fmt.Fprintf(w, "whotyped simulate --offline: %s\n", res.Scenario)
	if res.Expected.Notes != "" {
		fmt.Fprintf(w, "  %s\n", res.Expected.Notes)
	}
	fmt.Fprintf(w, "  events %d, tracks %d, subject %s\n\n", res.Events, res.Tracks, res.Subject)
	agent := v.Agent
	if agent == "" {
		agent = "-"
	}
	fmt.Fprintf(w, "score %d/100  class %s  level %s  mode %s  agent %s  categories %d\n", v.Score, v.Class, v.Level, v.Mode, agent, v.Categories)
	if v.Profile != "" {
		fmt.Fprintf(w, "allowlist profile %q matched, %d clue(s) suppressed\n", v.Profile, len(v.Suppressed))
	}
	fmt.Fprintln(w)
	WriteReasons(w, v.Reasons)
	for _, s := range v.Suppressed {
		fmt.Fprintf(w, "  suppressed %-24s %+4d  by profile %s\n", s.Clue, s.Weight, s.Profile)
	}
	fmt.Fprintln(w)
	want := res.Expected
	exp := fmt.Sprintf("score %d..%d class %s", want.ScoreMin, want.ScoreMax, want.Class)
	if want.Level != "" {
		exp += " level " + string(want.Level)
	}
	if want.Mode != "" {
		exp += " mode " + want.Mode
	}
	if res.Pass {
		fmt.Fprintf(w, "expected %s: PASS\n", exp)
	} else {
		fmt.Fprintf(w, "expected %s: FAIL (%s)\n", exp, strings.Join(res.Failures, "; "))
	}
}

// WriteReasons prints a clue table; shared with the online mode and report.
func WriteReasons(w io.Writer, reasons []clues.Clue) {
	if len(reasons) == 0 {
		fmt.Fprintln(w, "  (no clues)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  CLUE\tCATEGORY\tWEIGHT\tEVIDENCE")
	for _, r := range reasons {
		fmt.Fprintf(tw, "  %s\t%s\t%+d\t%s\n", r.ID, r.Category, r.Weight, r.Evidence)
	}
	tw.Flush()
}
