# Changelog

All notable changes to whotyped are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- `whotyped run`: daemon wiring readers (sshd log via journald or file, auditd
  via audisp socket or `audit.log`, `/proc` process and connection scanner)
  into one correlator, the scorer, the alert dispatcher and sinks; 4096-event
  drop-oldest queue; 2 s evaluation rate limit with immediate scoring on strong
  events; 30 s expiry tick emitting `agent_ended`; `state.json` restore and
  atomic save; graceful shutdown with sink flush.
- `run --replay events.jsonl` (any OS) and `run --once` (read log files from
  the start, then exit); `run --dry-run` prints alerts as JSON.
- Alert schema `whotyped.alert.v1` with events `agent_detected`,
  `agent_declared`, `agent_high`, `agent_still_active`, `agent_ended`,
  `freeze_violation`; classes `human`, `declared_agent`, `suspected_agent`.
- Seven clue families (banner, rhythm, pty, style, process, flags, network)
  plus identity; additive scoring with per-category caps; alert at 70 requires
  two categories; negative clues for interactive humans.
- Embedded rule packs: 20 agents, 18 client banners, 10 style patterns, 22 AI
  API hosts, allowlist profiles for Ansible, VS Code Remote, GitHub runners and
  others; override directories and `whotyped rules validate`.
- Freeze windows (cron + duration or start/end) raising `freeze_violation`.
- Sinks: rotated JSON Lines file, syslog, webhook (generic, Slack, Teams),
  email over SMTP with STARTTLS, Prometheus text exposition with `/healthz`.
- `whotyped check [--fix]`: sshd `LogLevel`/`AcceptEnv`, auditd rule and log,
  `/proc` readability, config and rules validation, per-family coverage;
  `--fix` installs the sshd drop-in and audit rules.
- `whotyped simulate`: offline replay of seven labelled scenarios embedded in
  the binary; online mode driving the system ssh client with 12 benign
  agent-shaped commands, a PTY human session, or a local marker process.
- `whotyped report`: per-session dedupe, totals, top-N by account / server /
  agent / key, top clues, per-agent breakdown, session timeline; table,
  Markdown and JSON output.
- Packaging: systemd unit with capability bounding set and sandboxing, deb and
  rpm via goreleaser, checksums, SBOM, cosign keyless signatures, GitHub
  provenance attestation.
- Detection content for other tools: Sigma, Wazuh and Falco rules in `deploy/`.
- Labelled dataset (`testdata/dataset/`) as the scorer's definition of done.

### Known limitations

- Linux only; parsers and replay run anywhere.
- Client banner clue needs sshd `LogLevel DEBUG1`.
- No keystroke timing (tlog / eBPF are on the roadmap); an agent told to slow
  down and allocate a PTY looks like a human.
- The shipped `vscode-remote` profile does not yet match the `vscode-remote`
  dataset scenario (scores 43 instead of <= 30).

[Unreleased]: https://github.com/whotyped/whotyped/compare/main...HEAD
