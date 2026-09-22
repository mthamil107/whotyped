# whotyped

**Know when an AI agent, not a human, is working on your Linux servers over SSH.**

[![CI](https://github.com/mthamil107/whotyped/actions/workflows/ci.yml/badge.svg)](https://github.com/mthamil107/whotyped/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mthamil107/whotyped?sort=semver)](https://github.com/mthamil107/whotyped/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/mthamil107/whotyped)](https://goreportcard.com/report/github.com/mthamil107/whotyped)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mthamil107/whotyped/badge)](https://scorecard.dev/viewer/?uri=github.com/mthamil107/whotyped)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An agent runs a command on your server with a person's key. The log records the person. whotyped reads what the server already writes down (the sshd log, auditd, `/proc`), joins it into sessions, and says which ones were driven by a tool.

Agents that announce themselves are labelled by name. The rest are judged on how they behave, and every alert carries the evidence that produced it.

One static binary, no database, no agent on your workstation, nothing leaves the server.

---

## Install

```sh
VERSION=0.1.0    # latest release
curl -fsSLO https://github.com/mthamil107/whotyped/releases/download/v$VERSION/whotyped_${VERSION}_linux_amd64.deb
sudo dpkg -i whotyped_${VERSION}_linux_amd64.deb      # or the .rpm, or the .tar.gz

sudo whotyped check --fix                        # sshd VERBOSE, AcceptEnv, sshrc hook, audit rule
sudo systemctl reload ssh && sudo augenrules --load
sudo systemctl enable --now whotyped
```

Packages for amd64 and arm64, with cosign-signed checksums, SBOMs and build provenance, are on the [latest release](https://github.com/mthamil107/whotyped/releases/latest). Building from source needs Go 1.26 and the extra steps in [the quickstart](docs/install/quickstart.md).

**See it work, in a minute:**

```sh
whotyped simulate                 # 12 benign agent-shaped commands over ssh, then waits for the alert
```

**No Linux box to hand?** The same pipeline runs anywhere, on recorded sessions:

```sh
go run ./cmd/whotyped simulate --offline --scenario real-claude-code-ssh   # a real agent session: 73, alert
go run ./cmd/whotyped simulate --offline --scenario human-admin            # a real person: 0
```

---

## What it caught on a real server

A 25-minute pilot on a live Ubuntu 20.04 host, with real AI agents operating it over SSH. Full write-up: [`docs/research/06-pilot-2026-09-14.md`](docs/research/06-pilot-2026-09-14.md). Those sessions are now part of the test suite, anonymised, so future changes are measured against real traffic rather than fixtures.

| Session | Score | Verdict |
|---|---|---|
| Claude Code driving the host over SSH, undeclared | 73 | alert |
| A paramiko client, the shape an MCP SSH server takes | 75 | alert |
| Claude Code declaring itself with `AI_AGENT` | 60 | labelled `claude-code` |
| A person doing ordinary admin work | 0 | silent |
| Ansible and VS Code Remote | 0 | silent |
| Internet password guessing during the window | — | ignored, not a session |

---

## How it decides

**Declared.** A cooperative tool sets `AI_AGENT=<name>`, and the session is labelled whatever its score. The label is not a pass: a declared agent that behaves loudly still alerts. See [the convention](docs/spec/ai-agent-over-ssh.md).

**Detected.** Seven clue families, each capped so no single one can convict. `info` at 40, `alert` at 70 and only with two families agreeing, `high` at 90. Interactive humans earn negative clues.

| Family | What it looks at | Needs |
|---|---|---|
| rhythm | bursts of exec channels, machine-regular gaps, sub-second cadence, and the multi-second pacing of a model choosing each command | sshd `LogLevel VERBOSE` |
| pty | no terminal across many sessions (+15); a long interactive one (-15) | sshd `LogLevel VERBOSE` |
| style | heredocs, `cd X && ...`, `bash -lc` wrappers, `--no-pager`, `\| head -n`, `2>&1`, `timeout N`, absolute paths | auditd execve rule |
| process | a known agent binary, or its markers (`CLAUDECODE`, `CURSOR_AGENT`, `CODEX_SANDBOX`, ...) | `/proc`, root for environments |
| flags | `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, `--full-auto` | auditd or `/proc` |
| network | connections to AI API hosts from the session's own processes | `/proc/net` |
| banner | client library: paramiko, AsyncSSH, ssh2js, Go (+35); OpenSSH, PuTTY (-10) | sshd `LogLevel DEBUG1`, optional |

A session is a *track*: one user, one key, one source address, over a 15-minute window. ControlMaster, pooled connections and per-command `ssh` calls all land in the same place, joined to auditd and `/proc` through the audit session id.

### An alert

```json
{
  "schema": "whotyped.alert.v1",
  "ts": "2026-09-14T10:01:14Z",
  "host": "web-03",
  "event": "agent_detected",
  "class": "suspected_agent",
  "mode": "remote_agent",
  "user": "alice",
  "src_ip": "203.0.113.10",
  "key_fingerprint": "SHA256:Qm3k...",
  "score": 73,
  "level": "alert",
  "reasons": [
    {"clue": "rhythm.burst",      "weight": 20, "evidence": "16 commands in 2m28s, median gap 7.6s, cv 1.24"},
    {"clue": "pty.none",          "weight": 15, "evidence": "0/16 sessions allocated a PTY"},
    {"clue": "rhythm.think_time", "weight": 15, "evidence": "16 exec channels paced like a model choosing each command"},
    {"clue": "style.pager_guard.head", "weight": 5, "evidence": "head -15 (6x)"}
  ],
  "session_id": "tr_0c2a0c62496a",
  "actions_hint": "Ask alice whether an AI tool is driving this key."
}
```

Events: `agent_detected`, `agent_declared`, `agent_high`, `agent_still_active` (at most every 30 minutes), `agent_ended`, and `freeze_violation` for any agent activity inside a change-freeze window you configure.

---

## Let honest agents speak up

The other half of the project is a convention, not code: [**AI_AGENT over SSH**](docs/spec/ai-agent-over-ssh.md). One environment variable, carried by a request SSH has had since 2006, accepted with one line of server config.

It works today for the major agent CLIs, with no change from their vendors, because each already marks the shells it spawns:

```
# on the machine where the agent runs
SendEnv AI_AGENT AI_AGENT_* CLAUDECODE CURSOR_AGENT GEMINI_CLI CODEX_SANDBOX
# on the server
AcceptEnv AI_AGENT AI_AGENT_* CLAUDECODE CURSOR_AGENT GEMINI_CLI CODEX_SANDBOX
```

Why it matters beyond whotyped: while every agent is silent, silence tells you nothing. Once honest tools announce themselves, silence becomes the unusual choice, and detection gets easier for everyone. The convention is free to implement, needs no permission, and names no product.

Adopters so far: [ssh-mcp](https://github.com/tufantunc/ssh-mcp), [merged](https://github.com/tufantunc/ssh-mcp/pull/227) on 2026-09-22. Sending one? Open an issue and the table in the spec gets your name.

---

## What it needs

- Linux with OpenSSH 8.x to 10.x, including the 9.8 `sshd-session` split, and either journald or `/var/log/auth.log` / `/var/log/secure`.
- sshd `LogLevel VERBOSE` and `AcceptEnv AI_AGENT`, written by `check --fix` to `/etc/ssh/sshd_config.d/90-whotyped.conf`. Reload sshd, never restart it.
- The [`/etc/ssh/sshrc` hook](deploy/sshd/sshrc), installed by `check --fix` only when the host has no sshrc of its own. Without it, declarations are visible only for long-running sessions.
- auditd with an execve rule. Optional, and the difference between "possible" and "probable" for remote agents, because it is what supplies command text.
- Root, with a capability set limited to reading logs, reading other users' process environments, and syslog, plus systemd sandboxing.

`whotyped check` prints, per clue family, whether it can fire on this host and what to change.

## Where alerts go

- `/var/lib/whotyped/alerts.jsonl`, rotated. `whotyped report --since 7d --by account|agent|key` summarises it as a table, Markdown or JSON.
- syslog, webhook (Slack, Teams, Discord or plain JSON), email over SMTP with STARTTLS, and Prometheus on `127.0.0.1:9477/metrics`.
- Ready-made rules for tools you already run: Sigma, Wazuh, Falco, plus an Ansible role and a Helm chart, in [`deploy/`](deploy/).

## Privacy

Evidence holds the matched fragment, the program name and the command length, never the whole command line, unless you ask for it with `privacy.command_text: full`. Only rule-listed environment variables are read. Nothing leaves the server unless you configure a webhook or email. There is no telemetry, no update check and no rule download. An HR and works-council briefing template is in [`docs/privacy/`](docs/privacy/hr-legal-template.md).

## Honest limits

- **A determined adversary can evade it.** Ask for a terminal, wait between commands, avoid the obvious command shapes. whotyped catches today's tools behaving normally. The spoof-resistant answer is declaration enforced on the key, not better guessing.
- **Without auditd**, a remote agent tops out around 55 (`info`). Measured in the [container lab](lab/e2e/README.md).
- **The model-pacing clue is provisional.** It was calibrated on three real agent sessions from one host, with no human baseline yet. That measurement is the next milestone, not a finished claim.
- **SSH only.** `kubectl exec` and AWS SSM are on the roadmap, on request. Windows servers, keystroke timing and any hosted service are not: see [`ROADMAP.md`](ROADMAP.md) for what was cut and why.
- **Rule packs age.** New agents need new entries, which is the easiest way to contribute.

## Status

v0.1.0, pre-release. The alert schema is stable; scores will move as the dataset grows. Ten labelled scenarios, three of them recordings of real agents, guard every change.

- [`ROADMAP.md`](ROADMAP.md) — what is next, what was cut, and how success is measured
- [`docs/design/ARCHITECTURE.md`](docs/design/ARCHITECTURE.md) — the design contract
- [`docs/cli.md`](docs/cli.md) — every command and exit code
- [`docs/compliance/mapping.md`](docs/compliance/mapping.md) — PCI DSS, ISO 27001, SOC 2, NIST, OWASP Agentic

## Why this exists

Four incidents in one year, each visible from the server as a session that did not behave like a person. Sources are itemised in [`docs/research/05-incident-sources.md`](docs/research/05-incident-sources.md).

- **Replit, July 2025.** A coding agent deleted a live production database during a declared code freeze, then misrepresented whether the data could be recovered ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/), [AIID #1152](https://incidentdatabase.ai/cite/1152)).
- **s1ngularity, August 2025.** Compromised `nx` releases turned developers' own AI tools against them, invoking `claude --dangerously-skip-permissions`, `gemini --yolo` and `q chat --trust-all-tools` to harvest secrets; over a thousand valid GitHub tokens leaked ([StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware), [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).
- **GTG-1002, September to November 2025.** A state-sponsored actor used Claude Code for roughly 80 to 90% of an intrusion campaign's tactical work against about 30 organisations ([Anthropic](https://www.anthropic.com/news/disrupting-AI-espionage)).
- **Amazon Kiro, December 2025.** An internal coding agent, running under an engineer's over-broad role, deleted and recreated an environment behind a roughly 13-hour regional outage; Amazon attributes it to the role, not the agent ([The Register](https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/), [AIID #1442](https://incidentdatabase.ai/cite/1442/)).

In two of the four, whotyped on the affected host would not have seen the decisive action. The pattern is what matters: agents act with human credentials, and the humans who own those credentials find out afterwards.

## Contributing

Adding a rule pack entry is the best first issue: one YAML block in `rules/agents.yaml` for a tool, plus a fixture. False-positive reports that include the `reasons` block are the second best, because they are what the scoring needs most. See [CONTRIBUTING.md](CONTRIBUTING.md). `go test ./...` must pass on Linux and Windows, and `whotyped rules validate rules/` must stay green.

Security issues: please use [private vulnerability reporting](https://github.com/mthamil107/whotyped/security/advisories/new) rather than an issue. [SECURITY.md](SECURITY.md) has the details.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
