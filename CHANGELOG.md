# Changelog

All notable changes to whotyped are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.1.0] - 2026-09-21

First public release. Pre-1.0: the alert schema and rule-pack format may
still change, and the `rhythm.think_time` clue is provisional pending human
baseline data from pilots.

### Found by the pilot on a real server (2026-09-14)

See `docs/research/06-pilot-2026-09-14.md`.

- New `rhythm.think_time` clue (+15): 8 or more SSH exec channels with a
  median gap of 1.5 to 30 s and a coefficient of variation of at least 0.5,
  the pacing of a model choosing each command. Real Claude Code and paramiko
  sessions went from 58 and 65 (`info`) to 73 and 75 (`alert`) on the live
  daemon. Provisional: tuned on three real sessions, pending human baselines.
- Session plumbing is no longer counted as activity: Ubuntu's MOTD scripts,
  the sshrc hook, `systemd --user` and everything they spawn are dropped, and
  the login shell sshd starts is recorded as the command it wraps, so its
  `-c` is not a tool-wrapper clue.
- Failed and unknown-user auditd logins no longer create tracks.
- `check` reports the OpenSSH version correctly on sshd builds without `-V`.
- Three anonymised real sessions added to the labelled dataset
  (`testdata/dataset/real-*`). The paramiko MCP fixture now scores 95.
- The Go module path is `github.com/mthamil107/whotyped`.

### Found by the end-to-end lab

- Declarations now reach whotyped for one-command-per-step agents. A new
  `/etc/ssh/sshrc` hook (`deploy/sshd/sshrc`) logs `AI_AGENT` with the
  session's address and port under the tag `whotyped-declare`; the sshd log
  reader parses it and the correlator attaches it only to an existing
  connection for the same user, address and port, rejecting it when
  journald's trusted `_UID` belongs to another user. `check --fix` installs
  the hook when the host has no sshrc and never edits an existing one; the
  Ansible role does the same; packages ship it under `/usr/share/whotyped/sshd/`.
- Inside a freeze window, a session that crosses alert or high after its
  violation alert is reported again with the current score and reasons,
  instead of waiting for the 30-minute re-alert.
- `check` warns when the auth log it would follow holds no sshd lines, reports
  style coverage only when auditd is active, and reports identity coverage
  only when the sshrc hook is installed.
- A background process that only exports `AI_AGENT` no longer turns an SSH
  track into a `local_agent` track.
- The Ansible role writes `/etc/ssh/sshd_config.d/90-whotyped.conf`, the same
  name `check --fix` uses (was `50-whotyped.conf`).
- New `lab/e2e`: real sshd, rsyslog, `/proc` and SSH clients in a container,
  with 14 asserted expectations across two passes.

### Security and hardening

- Self-declaration no longer silences detection: a `declared_agent` track that
  scores at alert or high also emits `agent_detected` / `agent_high` (class
  kept) and `agent_ended`, so it reaches every sink. `AI_AGENT` is accepted
  only from the session itself (accepted `SetEnv`, or a process attributed by
  audit session id, by parent sshd pid, or as the creator of a local track);
  processes placed on a track by user fallback record the value but do not
  declare, and the claim is withdrawn when the declaring process is gone.
- `Close session` (channel close) no longer closes the TCP connection in the
  correlator; pooled and ControlMaster sessions stay one connection on one
  fingerprint track. The post-auth "User child is on pid N" pid is indexed.
- Allowlist profiles: the Ansible profile matches the exact command shapes
  Ansible produces (anchored, with the `AnsiballZ` module run required); every
  shipped profile carries a required anchor clause; the match ratio counts
  SSH exec channels in its denominator; `rules validate` rejects a profile
  that suppresses rhythm/pty/style with no users, src_cidrs, fingerprints,
  required clause or banner clause; `check` and `rules validate` warn about
  profiles that match any source.
- Webhook errors never carry the URL path (the credential): `*url.Error` is
  unwrapped to scheme+host plus the inner cause. Teams cards and the Slack
  fallback text escape markdown.
- Attacker-controlled strings (comm, exe, argv0, `AI_AGENT`, env markers)
  are cleaned at ingestion: ANSI sequences stripped, control bytes replaced,
  comm 64 / paths 256 / `AI_AGENT` 64 bytes of `[A-Za-z0-9._@:+-]`, else
  `invalid-declaration`. auditd caps argv0/exe at 256 and comm at 64 bytes;
  `auditd.Replay` flushes stale groups every 1000 lines; `Parser.Feed` no
  longer copies its group list per line.
- Freeze windows: any verdict at info or above violates (not only
  `suspected_agent`), and `freeze_windows[].level` is honoured
  (`alert.Freeze.Level`, default high).
- Forced-command sessions (`command=` / `ForceCommand`) count as exec channels
  with the logged command as text.
- Pre-auth failures never create tracks or touch the per-user "most recent
  track"; they count on an existing open track and in a bounded (1024) per-IP
  LRU. A 10k-line brute force adds zero tracks.
- `pty.none` counts only shell sessions: `ssh -tt host cmd` on every call no
  longer cancels it (`Connection.PTYExecCount`, evidence notes the count).
- Supply chain: every GitHub Action pinned to a commit SHA with a version
  comment; Dependabot for actions and gomod weekly; CI checks `go mod tidy
  -diff`; `gopkg.in/yaml.v3` is a direct requirement.
- Race on the dropped-events counter fixed (`atomic.Int64`); `journalctl`
  child gets a minimal environment (PATH, LC_ALL=C); the jsonfile sink refuses
  symlinks and non-regular targets (O_NOFOLLOW on Linux); `check --fix`
  creates `/etc/audit/rules.d` 0750; `simulate` uses a per-run random marker
  path in `/tmp`; `readers.netconn.resolve` is `hostlist|none` (bool still
  accepted) and `rules.auto_update: true` is rejected as not implemented;
  provisional tracks absorbed by their keyed track release their dispatcher
  memo (`Dispatcher.Forget`); the syslog sink is closed on shutdown;
  `AF_NETLINK` dropped from the systemd unit; replay skips zero-timestamp
  events with a counted warning.
- Frozen contracts, additive only: `session.Connection.PTYExecCount`,
  `session.ProcSample.Attributed`, `alert.Freeze.Level`.

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
- `rhythm.think_time` has no human baseline yet; expect tuning after pilots.
- One real host tested (Ubuntu 20.04, OpenSSH 8.2) plus the container lab.

[Unreleased]: https://github.com/mthamil107/whotyped/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mthamil107/whotyped/releases/tag/v0.1.0
