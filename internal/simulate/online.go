package simulate

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/sinks/jsonfile"
)

// Options configures the online simulation.
type Options struct {
	Target     string        // ssh destination, e.g. alice@localhost; "" means localhost as the current user
	Scenario   string        // claude-bash | paramiko-mcp | local-agent | ansible | human
	Declared   bool          // send AI_AGENT=whotyped-simulate (needs AcceptEnv AI_AGENT on the server)
	Timeout    time.Duration // how long to wait for the alert; default 120s
	AlertsPath string        // alerts.jsonl written by the daemon on the target host
	Socket     string        // reserved for a daemon control socket; unused in v0.1
	JSON       bool          // print the winning alert as JSON instead of a table
	Stdout     io.Writer
	Stderr     io.Writer
	// Executable is the path used for the local-agent child; default os.Executable().
	Executable string
}

// SimMarkerPrefix is the start of the per-run marker file the benign
// commands create on the target and the cleanup removes. A random suffix
// (see newMarker) means nobody can pre-plant a symlink at a known path in
// the shared /tmp and have the simulation's heredoc write through it.
const SimMarkerPrefix = "/tmp/whotyped-sim-"

// newMarker returns a fresh marker path for one run.
func newMarker() string {
	var b [6]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand failing is not worth aborting a simulation over;
		// fall back to the pid and clock, still unique per run.
		return fmt.Sprintf("%s%d-%d.txt", SimMarkerPrefix, os.Getpid(), time.Now().UnixNano())
	}
	return SimMarkerPrefix + hex.EncodeToString(b[:]) + ".txt"
}

// AgentSubcommand is the hidden mode the local-agent scenario spawns:
// `whotyped __sim-agent --dangerously-skip-permissions` with CLAUDECODE=1.
const AgentSubcommand = "__sim-agent"

// agentCommandsFor returns the 12 benign, tool-shaped commands an agent's
// Bash tool typically emits: cd && chains, heredocs, pager guards, timeouts,
// sed -n. marker is the per-run file they create and read back.
func agentCommandsFor(marker string) []string {
	return []string{
		`cd /tmp && ls -la 2>&1 | head -n 20`,
		`cat <<'EOF' > ` + marker + `
whotyped simulate: benign marker file
EOF`,
		`cd /tmp && cat ` + marker + ` 2>&1 | head -n 5`,
		`systemctl status --no-pager ssh 2>&1 | head -n 5 || true`,
		`timeout 5 uname -a`,
		`sed -n '1,20p' /etc/hostname`,
		`git --no-pager --version 2>&1 | head -n 1`,
		`cd /tmp && df -h . 2>&1 | tail -n 2`,
		`timeout 5 ps -eo pid,comm 2>&1 | head -n 10`,
		`cd /tmp && grep -n whotyped ` + marker + ` 2>&1 | head -n 3`,
		`sed -n '1,5p' /etc/os-release 2>&1 | head -n 5`,
		`cd /tmp && wc -l ` + marker + ` 2>&1 | tail -n 1`,
	}
}

// humanCommands run inside one PTY session with human-like pauses.
var humanCommands = []string{"uptime", "sleep 4", "ls -la /tmp | head", "sleep 5", "id", "sleep 3", "df -h | head -n 3"}

// RunOnline drives the scenario and waits for the matching alert.
func RunOnline(ctx context.Context, o Options) int {
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Timeout <= 0 {
		o.Timeout = 120 * time.Second
	}
	if o.AlertsPath == "" {
		o.AlertsPath = "/var/lib/whotyped/alerts.jsonl"
	}
	scenario := Resolve(o.Scenario)
	if scenario == "" {
		scenario = "claude-bash-over-ssh"
	}
	target := o.Target
	if target == "" {
		target = "localhost"
	}
	user := targetUser(target)
	start := time.Now()

	marker := newMarker()
	banner(o.Stdout, scenario, target, o.Declared, marker)

	var err error
	switch scenario {
	case "local-agent-skip-flags":
		err = runLocalAgent(ctx, o)
	case "human-admin", "ansible":
		err = runPTY(ctx, o, target)
	case "claude-bash-over-ssh", "mcp-paramiko":
		err = runExecChannels(ctx, o, target, marker, scenario == "mcp-paramiko")
	default:
		fmt.Fprintf(o.Stderr, "simulate: scenario %q has no online variant (use --offline)\n", scenario)
		return ExitTimeout
	}
	if err != nil {
		var se *sshError
		if errors.As(err, &se) {
			fmt.Fprintf(o.Stderr, "simulate: %v\n", err)
			fmt.Fprintln(o.Stderr, "hint: the simulation uses BatchMode, so an ssh key for the target must already be authorised;")
			fmt.Fprintln(o.Stderr, "      try `ssh -o BatchMode=yes "+target+" true` first, or pass --target user@host.")
			return ExitSSH
		}
		fmt.Fprintf(o.Stderr, "simulate: %v\n", err)
		return ExitTimeout
	}

	benign := scenario == "human-admin" || scenario == "ansible"
	wait := o.Timeout
	if benign {
		// A human session should stay quiet; a shorter wait is enough to catch
		// a false positive without holding the operator for two minutes.
		wait = min(o.Timeout, 30*time.Second)
	}
	fmt.Fprintf(o.Stdout, "\nwaiting up to %s for an alert about %q in %s ...\n", wait.Round(time.Second), user, o.AlertsPath)
	best, code := waitForAlert(ctx, o, user, start, wait, benign)
	cleanup(ctx, o, target, scenario, marker)
	if best != nil {
		fmt.Fprintln(o.Stdout)
		printAlert(o.Stdout, *best, o.JSON)
	}
	switch {
	case benign && best == nil:
		fmt.Fprintln(o.Stdout, "no alert: as expected for a human-shaped session (exit 0)")
	case benign && best != nil:
		fmt.Fprintf(o.Stdout, "unexpected alert with score %d for a human-shaped session; consider an allowlist profile (exit 1)\n", best.Score)
	case code == ExitMatch:
		fmt.Fprintf(o.Stdout, "alert received with score %d (exit 0)\n", best.Score)
	case code == ExitMismatch:
		fmt.Fprintf(o.Stdout, "an alert arrived but scored only %d (exit 1)\n", best.Score)
		explainMissing(o.Stdout, *best)
	default:
		fmt.Fprintln(o.Stdout, "no alert arrived in time (exit 2). Is whotyped running on the target and writing to --alerts?")
		fmt.Fprintln(o.Stdout, "  check with: whotyped check   (LogLevel VERBOSE is required for rhythm/pty clues)")
	}
	return code
}

func banner(w io.Writer, scenario, target string, declared bool, marker string) {
	fmt.Fprintln(w, "whotyped simulate (online)")
	fmt.Fprintf(w, "  scenario %s, target %s\n", scenario, target)
	switch scenario {
	case "local-agent-skip-flags":
		fmt.Fprintln(w, "  Spawns a child of this binary that carries the markers an AI coding agent leaves on a host:")
		fmt.Fprintln(w, "  CLAUDECODE=1 in its environment and --dangerously-skip-permissions in its arguments.")
		fmt.Fprintln(w, "  Its process name is still \"whotyped\", so detection relies on the env and flags clues.")
	case "human-admin", "ansible":
		fmt.Fprintln(w, "  Opens one PTY session and runs a few slow, ordinary commands; expects no alert.")
	default:
		fmt.Fprintln(w, "  Runs 12 benign, agent-shaped commands (ls, cat, uname, sed -n, git --version), each on its")
		fmt.Fprintln(w, "  own ssh exec channel without a PTY, with 300-900 ms between them: the rhythm of a tool loop.")
	}
	if declared {
		fmt.Fprintln(w, "  AI_AGENT=whotyped-simulate is sent, so the session should be classified declared_agent.")
	}
	fmt.Fprintln(w, "  Nothing is modified except "+marker+", which is removed at the end.")
	fmt.Fprintln(w)
}

// sshError marks a failure to reach the target (exit 3).
type sshError struct{ err error }

func (e *sshError) Error() string { return "ssh: " + e.err.Error() }
func (e *sshError) Unwrap() error { return e.err }

func sshPath() (string, error) {
	p, err := exec.LookPath("ssh")
	if err != nil {
		return "", &sshError{errors.New("no ssh client on PATH")}
	}
	return p, nil
}

// sshArgs builds the client invocation. ControlMaster is off so every command
// is its own connection, which is what an agent's Bash tool does.
func sshArgs(o Options, target string, pty bool, cmd string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
	}
	if o.Declared {
		args = append(args, "-o", "SetEnv=AI_AGENT=whotyped-simulate")
	}
	if pty {
		args = append(args, "-tt")
	} else {
		args = append(args, "-T")
	}
	args = append(args, target, "--", "bash", "-lc", shellQuote(cmd))
	return args
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func runExecChannels(ctx context.Context, o Options, target, marker string, paramiko bool) error {
	ssh, err := sshPath()
	if err != nil {
		return err
	}
	agentCommands := agentCommandsFor(marker)
	for i, cmd := range agentCommands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		first := strings.SplitN(cmd, "\n", 2)[0]
		fmt.Fprintf(o.Stdout, "  [%2d/%d] %s\n", i+1, len(agentCommands), first)
		c := exec.CommandContext(ctx, ssh, sshArgs(o, target, false, cmd)...)
		c.Stdin = nil
		out, err := c.CombinedOutput()
		if err != nil {
			if i == 0 || isConnectFailure(err, out) {
				return &sshError{fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))}
			}
			// Later commands may fail for benign reasons (no systemd, no git).
			fmt.Fprintf(o.Stdout, "         (remote exit: %v)\n", err)
		}
		jitter := 300 + rand.IntN(600)
		if paramiko {
			jitter = 200 + rand.IntN(400) // pooled library clients are a little faster
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(jitter) * time.Millisecond):
		}
	}
	return nil
}

func runPTY(ctx context.Context, o Options, target string) error {
	ssh, err := sshPath()
	if err != nil {
		return err
	}
	script := strings.Join(humanCommands, "; ")
	fmt.Fprintf(o.Stdout, "  one PTY session: %s\n", script)
	c := exec.CommandContext(ctx, ssh, sshArgs(o, target, true, script)...)
	c.Stdin = nil
	out, err := c.CombinedOutput()
	if err != nil && isConnectFailure(err, out) {
		return &sshError{fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))}
	}
	return nil
}

// isConnectFailure recognises ssh's own exit status 255 and typical messages.
func isConnectFailure(err error, out []byte) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 255 {
		return true
	}
	s := strings.ToLower(string(out))
	return strings.Contains(s, "permission denied") || strings.Contains(s, "connection refused") ||
		strings.Contains(s, "could not resolve") || strings.Contains(s, "host key verification failed")
}

// runLocalAgent starts the marker child and leaves it running for the
// procfs reader to see; waitForAlert polls while it lives.
func runLocalAgent(ctx context.Context, o Options) error {
	exe := o.Executable
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	c := exec.CommandContext(ctx, exe, AgentSubcommand, "--dangerously-skip-permissions", "-p", "whotyped simulate")
	c.Env = append(os.Environ(), "CLAUDECODE=1", "CLAUDE_CODE_ENTRYPOINT=cli")
	if err := c.Start(); err != nil {
		return fmt.Errorf("start marker process: %w", err)
	}
	fmt.Fprintf(o.Stdout, "  marker process pid %d started (exits after 45 s)\n", c.Process.Pid)
	go func() { _ = c.Wait() }()
	return nil
}

// AgentMain is the body of the hidden __sim-agent mode: sit still until the
// parent kills us or 45 s pass. The environment and argv are the point.
func AgentMain() {
	time.Sleep(45 * time.Second)
}

// waitForAlert polls the alerts file every 2 s. It returns as soon as an
// alert at or above the alert threshold (70) is seen; otherwise the best
// alert below it, or nil after the wait.
func waitForAlert(ctx context.Context, o Options, user string, start time.Time, wait time.Duration, benign bool) (*alert.Alert, int) {
	deadline := time.Now().Add(wait)
	var best *alert.Alert
	for {
		all, err := jsonfile.ReadAll(o.AlertsPath, start.Add(-time.Second))
		if err != nil {
			fmt.Fprintf(o.Stderr, "simulate: reading alerts: %v\n", err)
		}
		for i := range all {
			a := &all[i]
			if a.User != user || a.Event == alert.EvEnded {
				continue
			}
			if best == nil || a.Score > best.Score {
				best = a
			}
		}
		if best != nil && best.Score >= 70 && !benign {
			return best, ExitMatch
		}
		if best != nil && benign {
			return best, ExitMismatch
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	switch {
	case best == nil:
		return nil, ExitTimeout
	case best.Score >= 70:
		return best, ExitMatch
	default:
		return best, ExitMismatch
	}
}

func cleanup(ctx context.Context, o Options, target, scenario, marker string) {
	if scenario != "claude-bash-over-ssh" && scenario != "mcp-paramiko" {
		return
	}
	ssh, err := sshPath()
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_ = exec.CommandContext(cctx, ssh, sshArgs(o, target, false, "rm -f "+marker)...).Run()
}

func printAlert(w io.Writer, a alert.Alert, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(a)
		return
	}
	fmt.Fprintf(w, "alert %s: score %d level %s class %s mode %s user %s src %s session %s\n",
		a.Event, a.Score, a.Level, a.Class, a.Mode, a.User, a.SrcIP, a.SessionID)
	WriteReasons(w, a.Reasons)
}

// explainMissing lists the clue families absent from the alert and the
// usual host-side reason for each.
func explainMissing(w io.Writer, a alert.Alert) {
	present := map[clues.Category]bool{}
	for _, r := range a.Reasons {
		if r.Weight > 0 {
			present[r.Category] = true
		}
	}
	var missing []string
	for _, c := range []clues.Category{clues.CatBanner, clues.CatRhythm, clues.CatPTY, clues.CatStyle, clues.CatProcess, clues.CatFlags, clues.CatNetwork} {
		if !present[c] {
			missing = append(missing, string(c))
		}
	}
	sort.Strings(missing)
	fmt.Fprintf(w, "clue families missing from the alert: %s\n", strings.Join(missing, ", "))
	if !present[clues.CatRhythm] || !present[clues.CatPTY] {
		fmt.Fprintln(w, "  likely cause: sshd LogLevel is not VERBOSE -> rhythm/pty clues unavailable (whotyped check --fix)")
	}
	if !present[clues.CatStyle] && !present[clues.CatFlags] {
		fmt.Fprintln(w, "  likely cause: no auditd execve rule -> style/flags clues unavailable (whotyped check --fix; augenrules --load)")
	}
	if !present[clues.CatBanner] {
		fmt.Fprintln(w, "  note: the banner family needs LogLevel DEBUG1 and is optional")
	}
}

// targetUser extracts the login from user@host, falling back to the local user.
func targetUser(target string) string {
	if i := strings.IndexByte(target, '@'); i > 0 {
		return target[:i]
	}
	if u, err := user.Current(); err == nil {
		name := u.Username
		if i := strings.LastIndexByte(name, '\\'); i >= 0 { // DOMAIN\user on Windows
			name = name[i+1:]
		}
		return name
	}
	return os.Getenv("USER")
}
