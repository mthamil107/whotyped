# End-to-end lab

This lab runs the real Linux binary against a real OpenSSH server, real
rsyslog output, real `/proc`, and real SSH clients. The unit tests and the
`simulate --offline` scenarios use hand-built events. This lab is where those
assumptions meet actual log lines.

```sh
sh lab/e2e/run.sh      # needs Docker and Go; about 8 minutes
```

`run.sh` builds `dist/whotyped-linux-amd64` and an Ubuntu 24.04 image, then
runs two passes. Each pass starts a fresh container, configures it with
`whotyped check --fix` like an operator would, starts sshd and the daemon,
drives the scenarios in `scenarios.sh`, and asserts on `alerts.jsonl`. Output,
alerts, daemon log, `check` and `check --fix` output, and `auth.log` are saved
under `lab/recordings/e2e-<timestamp>/`, which is gitignored. The exit status
is non-zero when any expectation fails.

## What it covers

| Pass | sshd | Extra | Scenarios |
|---|---|---|---|
| A | `LogLevel VERBOSE` | a default install | agent-shaped OpenSSH session, human PTY session, declared agent, paramiko exec channels, agent process with a skip-permissions flag, `ssh -tt` bypass with a spoofed `AI_AGENT=human`, stdin through the sshrc hook, forged declaration line |
| B | `LogLevel DEBUG1` | an active freeze window | paramiko with its banner visible, declared agent, human |

Every scenario uses its own Unix user, so tracks never mix.

## Results on 2026-09-14

All 14 expectations passed.

| Scenario | What whotyped reported |
|---|---|
| Agent-shaped OpenSSH session, no auditd | score 55, `info`: rhythm and `pty.none` only |
| Human PTY session | no alert |
| Declared agent via `SetEnv AI_AGENT` | `declared_agent`, agent `whotyped-simulate` |
| paramiko, one transport, 10 exec channels | score 55, `info`, one connection |
| Fake `claude --dangerously-skip-permissions`, `CLAUDECODE=1` | score 70, `alert`, `local_agent`, `?claude-code` |
| `ssh -tt` on every command plus background `AI_AGENT=human` | score 55, `pty.none` still fires, not declared, `remote_agent` |
| stdin piped through a session with the hook | arrives intact |
| Forged `whotyped-declare` line for a session that does not exist | ignored |
| paramiko at DEBUG1 inside a freeze window | `freeze_violation` at 60, then `agent_high` at 90 |
| Declared agent inside a freeze window | `freeze_violation`, class `declared_agent` |
| Human inside a freeze window | no alert |

## What the lab found

The first runs found three problems that fixture tests had not:

1. **Declarations were missed for one-command-per-step agents.** sshd does not
   log accepted environment variables below DEBUG2, and a short command ends
   before the 2-second `/proc` scan reads its environment. A `SetEnv
   AI_AGENT` client was classified `human`. Fix: the `/etc/ssh/sshrc` hook in
   `deploy/sshd/sshrc`, parsed by the sshd log reader.
2. **Escalations inside a freeze window were swallowed.** The violation went
   out at score 60 after four channels; the session reached 90 and nothing
   more was sent until the 30-minute re-alert. Fix: the dispatcher reports
   later alert and high crossings inside the window.
3. **`check` passed a silent log file and overstated style coverage.** An
   `auth.log` rsyslog could not write was reported as fine, and style clues
   were reported available from `/proc` alone. Fix: `check` now reads the
   log tail for sshd lines, and style coverage requires auditd.

## Limits

- No auditd in a container, so remote sessions get no command text. That is
  why agent-shaped sessions stop at 55; with auditd the fixture scenarios
  reach 75 to 95, and real agents on the 2026-09-14 pilot server reached 73
  to 80 (`docs/research/06-pilot-2026-09-14.md`). For an auditd lab of your
  own, see
  `lab/cloud-init-ubuntu.yaml` and `lab/cloud-init-rocky.yaml`.
- The `claude` here is a stand-in script, not the real CLI. It has the real
  process name, argv and environment marker, and nothing else.
- Outbound AI API connections are not exercised.
- These are scripted sessions, not recordings of real agents or real people.
  Phase 0 still needs those to measure false alarms.
