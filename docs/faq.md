# FAQ

**Can an agent evade whotyped?**
Yes. whotyped scores the default behaviour of today's tools: many short exec channels without a PTY, `bash -lc` wrappers, heredocs, agent process names, permission-skip flags, connections to AI APIs. An agent instructed to allocate a PTY, pause a few seconds between commands, avoid heredocs and never pass skip flags will usually stay under the alert threshold. Keystroke and timing based detection is known to be forgeable (arXiv:2601.17280 argues the general case). We are honest about this in every doc: the output is evidence for a human to look at, not proof. The durable answer is the cooperative `AI_AGENT` convention plus the spoof-resistant server-side variants (`docs/spec/ai-agent-over-ssh.md` §2.3), which tie the label to the credential rather than to behaviour.

**What about false alarms?**
Expect them in week one from Ansible, Terraform, VS Code Remote, backup and monitoring scripts, and the occasional very fast human. Each alert lists its `reasons` with weights, so you can see exactly why. Add an allowlist profile (by user, source CIDR, key fingerprint, banner or command pattern) that suppresses the specific clue ids; the alert then records what was suppressed. The threshold design helps: an alert needs 70 points from at least two categories, and interactive PTY use subtracts points. If you hit a false positive we did not anticipate, open an issue with the `reasons` block (template provided). We aim to answer within 14 days.

**Does it record what people type?**
No. It never sees keystrokes or terminal output. By default it writes redacted evidence: the matched fragment (for example the flag `--yolo`), the first word of a command and its length. Full command text is written only if you set `privacy.command_text: full`. With auditd enabled the kernel audit log contains full command lines regardless of whotyped, but that is auditd's data with its own access control. See `docs/privacy/hr-legal-template.md`.

**Does it phone home?**
No. There is no telemetry, no update check, no crash reporting. The only network connections are the sinks you configure (webhook, email, syslog, Prometheus scrape). You can confirm this with `ss -tnp | grep whotyped` on an idle host, or by reading the code; the engineering rules forbid any other outbound call.

**Why not eBPF?**
Because v0.1 must install on a stock host in five minutes with no kernel requirements, no BTF dependency and no CGO. sshd logs, auditd and `/proc` are available on every distro we target. eBPF is planned for v1.0 (pure Go via cilium/ebpf) to capture `AI_AGENT` at exec time, see outbound connections per process without polling, and remove the auditd dependency. Until then `whotyped check` tells you what coverage you have.

**Windows servers?**
Later. The parsers are portable and the daemon builds on Windows for development, but the readers are Linux-only in v0.1. Windows OpenSSH server logs and ETW are a different project. Kubernetes `kubectl exec`, `docker exec` and AWS SSM sessions on Linux come first (they have `auid=unset` and need different join keys).

**How is this different from Teleport?**
Teleport's Agentic Identity Framework gives enrolled agents their own identity and proxies their sessions. That is provisioning: it works when the agent is enrolled and Teleport is in the path. whotyped is detection: it runs on the target host and works when the agent is unknown, unenrolled or using a human's key. Use both if you have Teleport; whotyped covers the sessions that did not go through it.

**How is this different from Prempti (Falco) or agent hooks?**
Prempti intercepts Claude Code and Codex tool calls through the agents' own hook mechanism, on the machine where the agent runs. It needs the agent to cooperate and it cannot see an agent's Bash tool sshing to another server. whotyped sits on the server being acted on and needs nothing from the agent.

**How is this different from an EDR (CrowdStrike, Defender, SentinelOne)?**
EDRs have started inventorying and hooking AI agents, mainly on developer laptops and Windows/macOS. They answer "which agents are installed and what are they doing on this endpoint". whotyped answers "is this SSH session on this Linux server a person", attributes it to an account and key, and ships as an open-source package you can read. It is not a replacement for endpoint protection.

**Does it block anything?**
No. It is detect-only. If you want to act, use the webhook to open a ticket, page someone, or drive your own automation (for example `pkill -t pts/N`), and think hard about the false-positive rate first.

**Does it need root?**
Yes in v0.1: `/var/log/audit/audit.log` is `0600 root` and reading another user's `/proc/<pid>/environ` needs `CAP_SYS_PTRACE`. The systemd unit hardens what it can (`ProtectSystem=strict`, read-only paths, no new privileges). A least-privilege mode with `CAP_DAC_READ_SEARCH` + `CAP_SYS_PTRACE` and a group-readable audit log is on the list.

**What does a declared agent look like?**
If a client sends `AI_AGENT=claude-code` and sshd has `AcceptEnv AI_AGENT`, or the session shell carries `AI_AGENT` in its environment, whotyped emits `event=agent_declared`, `class=declared_agent`, `agent=claude-code` at level `info`. A declaration is a label, not a pass: the score is still computed, and if the behaviour alone reaches `alert` or `high` the usual `agent_detected` / `agent_high` events follow with `class=declared_agent`, so a loud declared agent still reaches Slack and email. A declaration is only accepted from the session itself (an accepted `SetEnv`, or a process joined to the session by audit session id or by being a child of the sshd session process); a stray `AI_AGENT=x sleep infinity` left in the background does not relabel the account's next session, and the label is withdrawn when the declaring process is gone. Values are limited to 64 bytes of `[A-Za-z0-9._@:+-]`; anything else is recorded as `invalid-declaration` and ignored.

**What is a freeze window?**
A named time range in the config during which any agent activity (declared, or anything scoring 40 or more, whatever class the scorer gave it) is emitted as `freeze_violation` at the window's `level` (default `high`). Useful for change freezes and release nights.

**Can a session make itself look like Ansible to get allowlisted?**
Not by decoration. Allowlist patterns are anchored to the whole command line and written for the exact shapes the automation produces, and every shipped profile requires at least one signature command (an `AnsiballZ_<module>.py` run, a path under `~/.vscode-server`, `rsync --server`, ...) before the match ratio even counts. The ratio's denominator is the larger of the audited commands and the SSH exec channels, so one channel whose children happen to match cannot carry a session of twenty. `whotyped rules validate` rejects a profile that suppresses rhythm, pty or style with no source restriction, required clause or banner clause, and `whotyped check` warns about every enabled profile that still matches any source until you add `users` or `src_cidrs`.

**How much does it cost to run?**
The daemon itself: a few MB of RAM and negligible CPU; it tails files and polls `/proc` on a timer. The costs that matter are sshd `VERBOSE` (a few extra lines per connection) and auditd's execve rule (1 to 2 KB per exec on disk and a small per-syscall overhead). `DEBUG1` is the expensive option and is off by default.

**Which agents does it know?**
The default rule pack covers Claude Code, Codex CLI, Gemini CLI, Cursor CLI, Aider, Goose, OpenCode, GitHub Copilot CLI, Amazon Q Developer CLI, Kiro CLI, plus the common MCP SSH servers by client banner and behaviour (`rules/agents.yaml`). Adding one is a YAML entry plus a fixture; see CONTRIBUTING.md.

**Can I run it without auditd?**
Yes. You lose command-style clues for remote sessions and the on-host agent process detection becomes polling-based via `/proc`. The worked examples drop from about 88 to 70 for a paramiko MCP server; the Claude Code Bash-tool-over-SSH case still reaches about 75 from sshd lines alone. `whotyped check` reports the reduced coverage.

**Where is the data?**
`/var/lib/whotyped/alerts.jsonl` (alerts), `/var/lib/whotyped/state.json` (open sessions, overwritten every 30 s), `/etc/whotyped/config.yaml`. Nothing else.
