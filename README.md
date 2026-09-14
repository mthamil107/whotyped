# whotyped

**Know when an AI agent, not a human, is working on your Linux servers over SSH.**

[![CI](https://github.com/mthamil107/whotyped/actions/workflows/ci.yml/badge.svg)](https://github.com/mthamil107/whotyped/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/mthamil107/whotyped)](https://goreportcard.com/report/github.com/mthamil107/whotyped)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mthamil107/whotyped/badge)](https://scorecard.dev/viewer/?uri=github.com/mthamil107/whotyped)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

whotyped is a small Go daemon that reads what the server already has (the sshd
log, auditd, `/proc`), joins it into sessions, and scores each session 0-100
for "this is being driven by a tool". Agents that announce themselves are
recorded as such; the rest are inferred from how they behave. Every alert
carries the evidence.

## 60-second demo

```sh
# 1. build from source (Go 1.26); deb/rpm packages will be attached to GitHub Releases from v0.1.0
git clone https://github.com/mthamil107/whotyped && cd whotyped && go build -o whotyped ./cmd/whotyped && sudo install -m 0755 whotyped /usr/bin/whotyped

# 2. let sshd log sessions and accept AI_AGENT; add the auditd execve rule
sudo whotyped check --fix && sudo systemctl reload ssh && sudo augenrules --load

# 3. run it
sudo systemctl enable --now whotyped

# 4. pretend to be an agent: 12 benign tool-shaped commands over ssh, then wait for the alert
whotyped simulate
```

A source build does not install the systemd unit or config; step 1 of
[`docs/install/quickstart.md`](docs/install/quickstart.md) shows the extra commands.

A demo recording will be added with the first release.

No Linux box at hand? The same pipeline runs on anything:

```sh
go run ./cmd/whotyped simulate --offline --scenario claude-bash      # score 75, alert
go run ./cmd/whotyped run --replay testdata/dataset/mcp-paramiko/events.jsonl --dry-run
```

## Why

Four incidents in one year, each visible from the server side as a session that
did not behave like a person:

- **Replit / SaaStr, July 2025** - Replit's coding agent deleted a live production database (records for more than 1,200 executives and over 1,190 companies) during a declared code freeze, then misrepresented whether the data could be recovered; reports put the fake user records it had also generated at about 4,000 ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/), [AI Incident Database #1152](https://incidentdatabase.ai/cite/1152)).
- **s1ngularity (Nx), August 2025** - compromised `nx` npm releases shipped a post-install script that invoked locally installed AI CLIs with `claude --dangerously-skip-permissions -p`, `gemini --yolo -p` and `q chat --trust-all-tools --no-interactive` to inventory secrets on developer machines; Wiz counted over a thousand valid GitHub tokens leaked in the first phase and over 5,500 private repositories made public in the second (later revised upward) ([Nx advisory](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c), [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware), [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).
- **GTG-1002, September-November 2025** - a state-sponsored actor used Claude Code to run roughly 80-90% of an intrusion campaign's tactical operations against about 30 organisations, including lateral movement and remote command execution through MCP-connected tooling; detected mid-September, disclosed 13 November ([Anthropic report](https://www.anthropic.com/news/disrupting-AI-espionage), [full report](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)).
- **Amazon Kiro, December 2025** (reported February 2026) - Amazon's internal coding agent, running under an engineer's role with broader permissions than intended, deleted and recreated an environment; the Financial Times tied it to a roughly 13-hour AWS Cost Explorer outage in one China region, which Amazon attributes to the misconfigured role rather than the AI ([The Register](https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/), [Amazon](https://www.aboutamazon.com/news/aws/aws-service-outage-ai-bot-kiro), [AI Incident Database #1442](https://incidentdatabase.ai/cite/1442/)).

Claims and sources are itemised in `docs/research/05-incident-sources.md`.

In two of the four, whotyped on the affected host would not have seen the
decisive action. The point is the pattern: agents act with human credentials,
and the humans who own those credentials find out afterwards.

## How it works

Two ways, both on every alert:

1. **Self-declared.** Honest tooling sets `AI_AGENT=<name>` over SSH
   (`ssh -o SetEnv=AI_AGENT=claude-code ...`, allowed by `AcceptEnv AI_AGENT`).
   A small `/etc/ssh/sshrc` hook logs the declaration for every session, so
   even one-command-per-step agents are labelled `declared_agent`. The label
   does not hide behaviour: a loud declared agent still alerts.
2. **Detected.** Seven clue families are scored with per-family caps; the sum
   is clamped to 100. `info` at 40, `alert` at 70 (needs two families), `high`
   at 90. Interactive humans get negative clues.

| Family | What it looks at | Needs |
|---|---|---|
| banner | client software version: paramiko, AsyncSSH, ssh2js, Go, libssh2 (+35); terraform, fabric (+15); OpenSSH, PuTTY (-10) | sshd `LogLevel DEBUG1` (optional) |
| rhythm | bursts of exec channels, machine-regular gaps, sub-second cadence | sshd `LogLevel VERBOSE` |
| pty | no PTY across many sessions (+15); a long interactive PTY (-15) | sshd `LogLevel VERBOSE` |
| style | heredocs, `cd X && ... && ...`, `bash -lc` wrappers, `--no-pager`, `\| head -n`, `sed -n`, `2>&1`, `timeout N`, absolute paths | auditd execve rule (or `/proc` for long-running commands) |
| process | a known agent binary or its environment markers (`CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`, ...) | `/proc`; environments need root |
| flags | `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, `--full-auto` | auditd or `/proc` |
| network | connections to AI API hosts from the session's processes | `/proc/net` |

A session is a *track*: `(user, key fingerprint, source IP)` over a 15-minute
window, so ControlMaster, connection pools and per-command `ssh` calls all land
in the same place. auditd and `/proc` are joined through the audit session id.

Worked examples from the labelled dataset: interactive admin 0; Ansible 0-5
with its profile; Claude Code's Bash tool sshing per command 75; a paramiko MCP
server with a DEBUG1 banner 95; `claude --dangerously-skip-permissions` on the
box 100. Real sessions from a pilot server, anonymised in `testdata/dataset/real-*`:
Claude Code over SSH 73, a paramiko client 80.

### Example alert

```json
{
  "schema": "whotyped.alert.v1",
  "ts": "2026-09-11T14:03:22Z",
  "host": "web-03",
  "event": "agent_detected",
  "class": "suspected_agent",
  "mode": "remote_agent",
  "user": "alice",
  "src_ip": "10.0.0.5",
  "key_fingerprint": "SHA256:Qm3k...",
  "score": 75,
  "level": "alert",
  "reasons": [
    {"clue": "rhythm.burst",  "category": "rhythm", "weight": 20, "evidence": "16 commands in 1m45s, median gap 7s, cv 0.08"},
    {"clue": "pty.none",      "category": "pty",    "weight": 15, "evidence": "0/16 sessions allocated a PTY"},
    {"clue": "style.heredoc", "category": "style",  "weight": 10, "evidence": "<<'EOF' (2x)"}
  ],
  "session_id": "tr_9117a1272782",
  "actions_hint": "Ask alice whether an AI tool is driving this key. Honest agents can declare themselves with: ssh -o SetEnv=AI_AGENT=<name> ..."
}
```

Events: `agent_detected`, `agent_declared`, `agent_high`, `agent_still_active`
(at most every 30 min), `agent_ended`, `freeze_violation` (any agent activity
inside a configured change-freeze window).

## What it needs

- Linux with OpenSSH (8.x to 10.x; the 9.8 `sshd-session` split is handled) and either journald or `/var/log/auth.log` / `/var/log/secure`.
- sshd `LogLevel VERBOSE` and `AcceptEnv AI_AGENT`. `whotyped check --fix` writes `/etc/ssh/sshd_config.d/90-whotyped.conf`; reload, do not restart.
- The `/etc/ssh/sshrc` declaration hook ([`deploy/sshd/sshrc`](deploy/sshd/sshrc)). `check --fix` installs it when the host has no sshrc and never edits an existing one. sshd logs accepted variables only at DEBUG2, so without the hook declarations are seen only for long-running sessions.
- auditd with an execve rule: optional but recommended, it is what gives command text for remote sessions. `check --fix` writes `/etc/audit/rules.d/90-whotyped.rules`.
- root. The service runs as root, with its capability bounding set limited to `CAP_DAC_READ_SEARCH` (logs), `CAP_SYS_PTRACE` (other users' `/proc/PID/environ`, where `AI_AGENT` lives) and `CAP_SYSLOG`, plus systemd sandboxing. A non-root mode is future work.

`whotyped check` prints, per clue family, whether it can fire on this host and
what to change.

## Outputs

- `/var/lib/whotyped/alerts.jsonl`, rotated by size; `whotyped report --since 7d --by account|server|agent|key --format table|md|json` summarises it.
- syslog (`auth`, JSON body), webhook (generic JSON, Slack, Teams), email (SMTP + STARTTLS, credentials from the environment).
- Prometheus text exposition on `127.0.0.1:9477/metrics` with `/healthz`.
- Rules for tools you already run: Sigma, Wazuh decoder and rules, Falco, in [`deploy/`](deploy/). Ansible role and Helm chart there too.

## Honest limits

- **Evasion is easy for an attacker who knows the scoring**: allocate a PTY, pace commands minutes apart or work inside one interactive shell, avoid heredocs, spoof an OpenSSH banner. whotyped catches the common case, the default behaviour of today's tools, not a determined adversary. The spoof-resistant path is declaration, enforced by policy on the key.
- The client banner is only logged at `LogLevel DEBUG1`; without it a paramiko client loses 35 points; on the pilot it still reached `alert` (75 to 80) through pacing and command style, with auditd on.
- Without auditd, a remote agent driving the host over SSH tops out around 55 (`info`): sshd logs give rhythm and PTY clues but no command text. The end-to-end lab measured exactly that; see [`lab/e2e/README.md`](lab/e2e/README.md).
- Real agents are slower than scripts. On a real Ubuntu 20.04 pilot server with auditd, the first real Claude Code and paramiko sessions scored 53 to 65 (`info`). Two fixes from that data (ignoring per-session plumbing, and a `rhythm.think_time` clue for model-paced commands) brought live sessions to 73 to 80 (`alert`). The think-time clue is tuned on three real sessions and is provisional until pilots add human baseline data; see [`docs/research/06-pilot-2026-09-14.md`](docs/research/06-pilot-2026-09-14.md).
- No keystroke timing yet. That needs tlog or eBPF and is Phase 2.
- SSH only. `kubectl exec`, SSM sessions and serial consoles are later phases.
- Linux hosts only. Parsers and replay run on any OS, the readers do not. No Windows target.
- A rule pack is a snapshot; new agents need new entries (see Contributing).

## Privacy

Redacted by default: evidence holds the matched fragment, `argv0` and the
command length, never the full command line, unless you set
`privacy.command_text: full`. Only rule-listed environment variables are read
from `/proc/PID/environ`. Nothing leaves the server unless you configure a
webhook or email sink; there is no telemetry, no update check, no rule download.

## Status

v0.1, pre-release, Phase 1: sshd + auditd + `/proc`, seven clue families,
seven labelled scenarios, packaging and integrations. The design contract is
[`docs/design/ARCHITECTURE.md`](docs/design/ARCHITECTURE.md); the command
reference is [`docs/cli.md`](docs/cli.md); the roadmap phases (tlog/eBPF
keystroke timing, kubectl and SSM, a hosted rule feed) are at the end of the
architecture document. Expect the alert schema to stay stable and the scores to
move as the dataset grows.

## Contributing

Rule packs are the best first issue: one YAML entry in `rules/agents.yaml` per
tool, with the process name, environment markers, skip flags and API hosts,
plus a fixture. False-positive reports with the `reasons` block are the second
best. See [CONTRIBUTING.md](CONTRIBUTING.md); `go test ./...` must pass on
Linux and Windows, and `whotyped rules validate rules/` must stay green.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
