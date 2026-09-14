# whotyped v0.1 — Architecture and build design

Status: accepted 2026-09-11. This is the contract the v0.1 code follows.
Pure Go, `CGO_ENABLED=0`. Linux readers behind build tags; parsers are portable and fixture-tested.

## 1. Critique of the plan (and what we changed)

1. **Session correlation was hand-waved.** sshd, PAM, auditd and `/proc` share no single key. We correlate in stages using keys that exist: sshd's `(user, src_ip, src_port)` tuple (in `Accepted …` and `Disconnected from user …`), the per-connection sshd child PID in the syslog tag, auditd `USER_START`/`USER_LOGIN` (`pid=`, `ses=`, `addr=`, `acct=`), execve records with `ses=`, and `/proc/PID/sessionid` + `/proc/PID/loginuid` (readable without auditd). Without auditd we degrade to `(user, src_ip)` + timing.
2. **OpenSSH 9.8 split.** Per-connection process is `sshd-session[pid]` since 9.8; 10.0 adds `sshd-auth`. The parser accepts all three program names; PID is only a secondary key. Fixtures for 8.9, 9.6, 9.8, 10.0.
3. **journald without cgo.** Shell out to `journalctl -f -o json` (primary, restart with backoff, `--cursor-file`), fall back to tailing `/var/log/auth.log` or `/var/log/secure`. Auto-detect.
4. **auditd exclusivity.** Tail `/var/log/audit/audit.log` in v0.1 (root or group read). `check --fix` installs the execve rule. Audisp plugin later. Without auditd, style/flag clues for remote sessions are lost; `check` reports detection coverage honestly.
5. **Scoring: additive weights with per-category caps.** No single category can reach 70; alert requires two contributing categories. Negative clues (PTY interactive, human banner) keep quirky humans under 40.
6. **Window key.** Connection = `(user, ip, port)`; Track (15-min window) = `(user, key_fingerprint or "-", src_ip)`. Rhythm counts exec channels (`Starting session: command`), not TCP connections, so ControlMaster is caught.
7. **Human-in-the-loop agents are agents.** A laptop Claude Code whose Bash tool sshes to prod presents only rhythm, no-PTY and style clues. Those three together must reach 70. Added clue `style.tool_wrapper` (`bash -lc`, `sh -c`).
8. **Two threat shapes.** `mode: local_agent | remote_agent | unknown` on every alert. Local agents are attributed to an SSH session via `/proc/PID/sessionid`.
9. **Privacy default: redacted, not hashed.** Evidence contains the matched fragment, argv0 and command length, never the full line. `privacy.command_text: redacted|full|none`.
10. **Simulate must be honest.** `--offline` feeds fixture events through the real pipeline (CI, any OS). Online mode uses the system `ssh` client against localhost with ControlMaster off, 12 benign agent-shaped commands, then waits for a matching alert. Exit 0 only if the alert arrived.
11. **State.** `/var/lib/whotyped/state.json` (atomic write every 30 s): open tracks, journal cursor, audit offset, dedupe keys. Alerts to `alerts.jsonl` (rotated). No database.
12. **Missing pieces added.** Alert dedupe and re-alert policy; timestamp normalisation; log-line injection defence (never re-parse text found inside another record); count `Connection closed by authenticating user` bursts; labelled dataset in `testdata/dataset/` as the scorer's definition of done.

Two caveats verified during research (see `docs/research/03-ssh-auditd-proc.md`): sshd logs the client software version only at `LogLevel DEBUG1`, and it does not log accepted `SetEnv` variables. So in v0.1 the banner clue is available only with DEBUG1 (or a passive sniff later), and the declared-agent signal comes from the procfs reader finding `AI_AGENT` in the session shell's environment, plus a PAM-free `ForceCommand`-less path documented in the spec.

## 2. Layout

```
cmd/whotyped/                 subcommands: run, simulate, report, check, rules, version
internal/config/              Load(path) (*Config, error); defaults; validation
internal/event/               Event + Kind (shared by readers and correlator)      [frozen]
internal/session/             Track, Connection, Correlator
internal/clues/               one file per clue family: banner rhythm pty style procs netconn flags wrapper
internal/score/               Scorer: Track + rules -> Verdict; thresholds; allowlist
internal/rules/               YAML rule packs + allowlist profiles, schema v1, embedded defaults
internal/readers/             Reader interface; sshlog/ auditd/ procfs/
internal/alert/               Alert JSON schema v1, Sink, Dispatcher (dedupe, re-alert)
internal/sinks/               jsonfile syslog webhook email prom
internal/state/               state.json atomic load/save
internal/simulate/            offline + online runners
internal/report/              aggregates alerts.jsonl
internal/check/               sshd_config, auditd, permissions, coverage
internal/version/             ldflags-injected
rules/                        embedded default packs: agents.yaml banners.yaml styles.yaml apihosts.yaml allowlist.yaml
testdata/                     sshlog/ auditd/ procfs/ dataset/
deploy/                       systemd unit, audit.rules, sigma/, wazuh/, falco/, ansible/, helm/
```

## 3. Core types (frozen in `internal/event`, `internal/session`, `internal/clues`, `internal/score`, `internal/alert`)

See the Go source; the JSON alert schema is `whotyped.alert.v1`:

```json
{
  "schema": "whotyped.alert.v1",
  "ts": "2026-09-11T14:03:22.114Z",
  "host": "web-03",
  "event": "agent_detected",
  "class": "suspected_agent",
  "mode": "remote_agent",
  "user": "alice",
  "src_ip": "10.0.0.5",
  "key_fingerprint": "SHA256:Qm3k…",
  "agent": "",
  "score": 82,
  "level": "alert",
  "reasons": [
    {"clue":"rhythm.burst","category":"rhythm","weight":20,"evidence":"14 exec channels in 92s, median gap 640ms, cv 0.21"},
    {"clue":"pty.none","category":"pty","weight":15,"evidence":"0/14 sessions allocated a PTY"}
  ],
  "suppressed": [],
  "session_id": "tr_9f31c2a7b8e4",
  "connections": 1,
  "window": {"start":"2026-09-11T13:50:00Z","end":"2026-09-11T14:05:00Z","execs":14},
  "freeze_window": null,
  "actions_hint": "Ask alice whether an AI tool is driving this key. …"
}
```

Events: `agent_detected | agent_declared | agent_high | agent_still_active | agent_ended | freeze_violation`.
Classes: `human | declared_agent | suspected_agent`. Levels: `info (>=40) | alert (>=70) | high (>=90)`.

## 4. Pipeline

```
readers (goroutines) -> chan event.Event (buffered, drop-oldest with counter)
  -> Correlator (single goroutine, owns all Track state)
      -> Scorer.Evaluate on change (rate-limited to 2 s, immediate on strong events)
          -> Verdict -> alert.Dispatcher (dedupe / re-alert policy) -> sinks (own goroutine + bounded queue)
  ticker 30 s: expire tracks (LastSeen + window), emit agent_ended, snapshot state
```

## 5. Scoring spec

Score = min(100, sum over categories of min(cap, sum of clue weights)), then negative clues subtracted, floor 0.

| Category | Clue | Weight | Cap |
|---|---|---|---|
| banner | banner.library (paramiko, AsyncSSH, ssh2js, Go, russh, libssh2) | 35 | 35 |
| banner | banner.automation (terraform, fabric) | 15 | |
| banner | banner.human (OpenSSH_, PuTTY, WinSCP, MobaXterm) | -10 | |
| rhythm | rhythm.burst (>=6 exec channels in 5 min) | 20 | 45 |
| rhythm | rhythm.regular (CV of gaps < 0.35, >=6 samples) | 10 | |
| rhythm | rhythm.subsecond (median gap < 1.5 s) | 10 | |
| rhythm | rhythm.sustained (>=25 exec channels in window) | 10 | |
| pty | pty.none (>=3 sessions, none with PTY) | 15 | 15 |
| pty | pty.interactive (PTY shell > 5 min) | -15 | |
| style | style.heredoc | 10 | 30 |
| style | style.compound (cd X && … with >=2 operators, len > 80) | 10 | |
| style | style.tool_wrapper (bash -lc, sh -c) | 8 | |
| style | style.pager_guard.{nopager, head, tail, sed_range, stderr_merge, timeout} (--no-pager, \| head -n, \| tail -n, sed -n, 2>&1, timeout N) | 5 each, max 15 | |
| style | style.abs_paths | 5 | |
| process | proc.agent_name | 45 | 45 |
| process | proc.agent_env | 40 | |
| flags | proc.skip_flags | 25 | 25 |
| network | net.ai_api (attributed to track ses/uid) | 30 | 30 |
| network | net.ai_api_unattributed | 15 | |

Rules: `alert` needs at least two categories > 0. Negative clue `pty.interactive` is dropped when `process` > 0. `pty.none` counts only shell sessions as PTY sessions: an exec channel that forced a terminal (`ssh -tt host cmd`, `Connection.PTYExecCount`) neither cancels it nor starts the `pty.interactive` clock, and the evidence says how many channels did so.

Declared agents: a declaration (`AI_AGENT`) changes the class to `declared_agent`, raises the level to at least info, and never lowers it. The dispatcher emits one `agent_declared` (info) per track and then treats the track like any other: when the score alone reaches 70/90 it emits `agent_detected` / `agent_high` with `class=declared_agent`, follows the `agent_still_active` cadence and ends it with `agent_ended`, so a loud declared agent reaches every sink. A declaration is accepted only from the session itself: an accepted `SetEnv AI_AGENT` on a connection, or `AI_AGENT` in the environment of a process attributed to the track by audit session id, by having the connection's sshd child (or an attributed process) as parent, or by being the process that created a local track. A process placed on a track only because it is the user's most recent one (`userLast`) records the value in `ProcSample.Env` but does not declare (`ProcSample.Attributed`). `Track.DeclaredAgent` is recomputed from the connections and attributed live processes on every change, so when the declaring process is gone and nothing else declares, the claim is withdrawn. Values are capped at 64 bytes of `[A-Za-z0-9._@:+-]`; anything else is stored as `invalid-declaration` and never becomes a claim.

Freeze windows: inside an active window any declared activity, or any verdict at level info or above (score >= 40, whichever class the scorer chose), is a `freeze_violation` at the window's configured `level` (default high, `alert.Freeze.Level`); follow-ups keep that level. One violation per (track, window), then the `agent_still_active` cadence. Re-alert: on first crossing of 40/70/90, then at most one `agent_still_active` per 30 min, `agent_ended` on expiry.

Attacker-controlled text (process names, executable paths, `AI_AGENT`, banners) is cleaned at ingestion (`internal/clean`: ANSI sequences stripped, control bytes replaced, comm 64 / paths 256 bytes) in the procfs reader, the auditd parser and the correlator, and chat sinks escape the markdown their cards render. Pre-auth failures (`ssh.auth_fail`) never create tracks or touch `userLast`; they are counted on an existing open track of the same user and source and in a 1024-entry per-IP LRU.

Worked examples (expected score): human admin interactive 0; Ansible run 0–5 after profile; VS Code Remote ~8 after profile; Claude Code Bash tool over SSH 75; MCP paramiko server 88 (70 without auditd); claude on the box with skip flag 100.

## 6. Allowlist profiles

Match on users, src_cidrs, fingerprints, banner_regex, argv0_regex, cmd_regex, path_regex with `min_match_ratio`; `suppress:` lists clue ids or categories; optional `max_score`. Profiles never suppress process, flags or `env.ai_agent` unless `allow_agent_processes: true`.

## 7. Commands

- `whotyped run --config … [--once] [--dry-run] [--replay events.jsonl]` exit 0/1 (config)/3 (no reader).
- `whotyped simulate [--target user@host] [--offline] [--scenario claude-bash|paramiko-mcp|local-agent|ansible|human] [--declared] [--timeout 120s] [--alerts path] [--json]` exit 0 alert >=70, 1 alert < 70, 2 timeout, 3 ssh failed.
- `whotyped report [--since 7d] [--by account|server|agent|key] [--format table|json|md] [--session id]` exit 0/1/2.
- `whotyped check [--fix] [--json] [--probe]` exit 0 pass, 1 degraded, 2 cannot run, 4 fix needs root.
- `whotyped rules validate [dir]`, `whotyped version`.

## 8. Work breakdown

T0 contracts (lead) → T1 sshlog, T2 auditd, T3 procfs/netconn, T4 correlator+clues+scorer+dataset (critical path), T5 rules+config+check, T6 alert dispatcher+sinks+state, T7 cmd+simulate+report+deploy. Integration: contracts → T4 against hand-written events → readers with fixtures → `run --replay` on Windows → dispatcher + jsonfile → `simulate --offline` green → config/rules/check → cross-compile → two VMs → tag v0.1.0.
