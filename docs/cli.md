# whotyped command reference

One static binary, subcommands parsed with the standard library. Every command
accepts `-h`. The configuration file is `/etc/whotyped/config.yaml`, overridden
by `$WHOTYPED_CONFIG`, overridden by `--config`. A missing file is not an error:
built-in defaults apply (`deploy/config.example.yaml` documents every key).

## whotyped run

```
whotyped run [--config file] [--once] [--dry-run] [--replay events.jsonl]
```

Starts the daemon: sshd log reader (journald or file), auditd reader (audisp
socket or `audit.log`), `/proc` scanner, one correlator goroutine, the scorer,
the alert dispatcher and the configured sinks. State is restored from
`<state_dir>/state.json` at start (open tracks, dedupe keys, audit.log offset)
and saved every 30 s and on shutdown. SIGINT/SIGTERM stop the readers, flush
the sinks (5 s budget) and save state.

| Flag | Meaning |
|---|---|
| `--once` | Read the configured sshd log file and `audit.log` from the start, take one `/proc` snapshot, process everything, exit. journald is not consulted; export it with `journalctl -o json > file` and set `readers.sshlog.file`. |
| `--dry-run` | Print every alert as one JSON line on stdout. No sinks, no state file, no metrics listener. |
| `--replay FILE` | Feed an `events.jsonl` (the format under `testdata/dataset/`) through the pipeline instead of readers. Works on any OS; event timestamps drive the clock. The final verdict per track is logged at the end. |

Exit codes: `0` clean stop, `1` configuration or rule-pack error (the message names the key), `3` no reader could start (not Linux, or no readable log source).

Logging goes to stderr as `slog` text at `log_level`.

Example, on a laptop:

```sh
whotyped run --replay testdata/dataset/mcp-paramiko/events.jsonl --dry-run
```

## whotyped simulate

```
whotyped simulate [--offline] [--scenario NAME|list] [--target user@host] [--declared]
                  [--timeout 120s] [--alerts PATH] [--json]
```

Offline (`--offline`, any OS, no ssh): replays an embedded scenario through the
real correlator and scorer with the shipped rule pack, prints the verdict and
clue table, and compares it with the scenario's `expected.json`.

| Scenario | Alias | Expected |
|---|---|---|
| `human-admin` | `human` | 0..10, human |
| `ansible` | | 0..20, human (profile) |
| `vscode-remote` | `vscode` | 0..30, human (profile) |
| `claude-bash-over-ssh` | `claude-bash` | 70..85, suspected_agent, alert |
| `mcp-paramiko` | `paramiko-mcp` | 80..95, suspected_agent, alert |
| `local-agent-skip-flags` | `local-agent` | 95..100, suspected_agent, high |
| `declared-agent` | `declared` | declared_agent |

Online (default): drives the system `ssh` client against `--target` (default
`localhost`, current user, BatchMode, ControlMaster off) and then polls
`--alerts` (default `sinks.jsonfile.path`) every 2 s for an alert about the
target user.

- `claude-bash` (default) and `paramiko-mcp`: 12 benign, tool-shaped commands, one exec channel each, no PTY, 300-900 ms apart. Creates and removes `/tmp/whotyped-sim.txt`.
- `human` and `ansible`: one PTY session with slow commands; expects **no** alert (waits at most 30 s).
- `local-agent`: spawns `whotyped __sim-agent --dangerously-skip-permissions` with `CLAUDECODE=1` for 45 s. The process name stays `whotyped`, so this exercises the env and flags clues, not `proc.agent_name`.
- `--declared` adds `-o SetEnv=AI_AGENT=whotyped-simulate`; needs `AcceptEnv AI_AGENT` on the server.

Exit codes: `0` alert with score >= 70 (or, for human/ansible, no alert), `1` an alert arrived below 70 (the output lists the missing clue families and the likely host-side cause), `2` timeout or unknown scenario, `3` ssh client missing or connection refused (check keys; the run uses BatchMode).

## whotyped report

```
whotyped report [--alerts PATH] [--since 7d|RFC3339] [--until ...] [--by account|server|agent|key]
                [--format table|json|md] [--session ID] [--min-level info|alert|high] [--top 10]
```

Reads `alerts.jsonl` and its rotated siblings (`.1`, `.2`, ...), folds alerts
into one row per `session_id` (max score and level, first and last timestamp,
distinct clues, declared beats suspected beats human), then prints totals
(sessions by class, alerts by level, freeze violations), the top N by the chosen
dimension with declared/suspected counts and mean/max score, the five most
frequent clues, a per-agent breakdown and the session list.

`--session ID` prints that session's alert timeline with reasons instead.
`--format md` is meant to be pasted into a weekly mail; `--format json` is a stable struct.

Exit codes: `0` report produced, `1` no alerts in the range (or unknown session), `2` bad flag or unreadable file.

## whotyped check

```
whotyped check [--config file] [--sshd-config file] [--fix] [--json] [--probe]
```

Inspects the config and rule packs, sshd version and effective `LogLevel` /
`AcceptEnv`, the sshd log source, auditd rules and log readability, `/proc`
readability (root or not), the state directory, and prints which of the eight
clue families can fire on this host.

| Flag | Meaning |
|---|---|
| `--fix` | Write `/etc/ssh/sshd_config.d/90-whotyped.conf` (LogLevel VERBOSE, AcceptEnv AI_AGENT) and `/etc/audit/rules.d/90-whotyped.rules`, run `sshd -t`, print the reload commands. Never restarts anything. Linux, root. |
| `--probe` | Also run `sshd -T` for the effective settings (root). |
| `--sshd-config FILE` | Parse this file instead of `/etc/ssh/sshd_config` (useful on a laptop to review a server's config). |
| `--json` | Machine-readable report. |

Exit codes: `0` pass, `1` degraded (whotyped runs but some clue families cannot fire; `WARN*` marks the optional DEBUG1 banner), `2` cannot run, `4` `--fix` needs root. On non-Linux the platform probes report `skip` and the exit code is 1 or 2.

## whotyped rules

```
whotyped rules validate [dir ...]
whotyped rules list [--config file]
```

`validate` loads the embedded packs plus the given directories (the pack the
daemon would run with) and reports every problem: bad ids, invalid regexes,
unknown agents, profiles that try to suppress process/flags/identity clues
without `allow_agent_processes`. Exit `0` valid, `1` problems.

`list` prints every agent id with counts of process names, env markers, skip
flags, API hosts and banners, plus pack totals.

## whotyped version

Prints `whotyped <version> (<commit>, <date>, <go> <os>/<arch>)`. Values come
from `-ldflags -X` (Makefile, goreleaser); a tree build prints `dev`.

## Exit codes at a glance

| Command | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| run | stopped cleanly | config / rules error | | no reader | |
| simulate | alert >= 70 (or none, for human) | alert < 70 | timeout / unknown scenario | ssh failed | |
| report | report printed | nothing in range | error | | |
| check | pass | degraded | cannot run | | fix needs root |
| rules validate | valid | problems | usage | | |
| any | | | usage / unknown command | | |
