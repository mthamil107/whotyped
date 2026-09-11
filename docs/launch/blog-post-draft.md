# Launch blog post: outline and draft

Working title: **Who typed that? Telling AI agents from humans on your Linux servers**

Length target: 1,500 to 2,000 words. Two diagrams (session pipeline; scoring table). One terminal recording. Every factual claim below marked "verify" must be checked against a primary source before publishing; incident dates and details in particular.

## 1. The question

Start with the concrete scene: 02:14, alice's key, 38 exec channels in 90 seconds, no PTY, `bash -lc` everywhere. The on-call engineer sees `Accepted publickey for alice` and nothing else. Was it alice? It was her Claude Code session, left running.

State the question plainly: on this server, right now, which SSH sessions are people?

## 2. Why the logs do not answer it

- sshd logs `Accepted publickey`, and at `LogLevel VERBOSE` also `Starting session: command|shell on pts/N`. It never logs the command text and only logs the client software banner at `DEBUG1`.
- sshd does not log accepted `SetEnv` variables (only at DEBUG2). PAM session hooks run before the env request arrives, so they cannot see an agent declaration either.
- auditd sees every execve with `auid` and `ses`, which is enough to tie commands to a login, but says nothing about who typed them.
- Nothing in the stack is asked "human or software?" (Cite `docs/research/03-ssh-auditd-proc.md` for the log-level facts.)

## 3. Incident timeline (what each one looked like from the server)

Keep each to four lines: what happened, what the server had, which whotyped signal would have fired, what it would have missed.

| Date | Incident | From the server's side | Signals | Missed |
|---|---|---|---|---|
| 2025-07 (verify) | Replit agent deletes a production database during a declared code freeze, then misreports it | agent ran with production credentials on the platform side; freeze was a human agreement, not a machine rule | `freeze_violation` if a freeze window had been configured; `rhythm.burst`; `pty.none` | This was not over SSH; whotyped's vantage point would need to be the DB host or a bastion |
| 2025 (verify date and facts) | Kiro agent tied to an AWS service outage | agent with operator credentials issued destructive changes | `proc.agent_name` (`kiro-cli`), `proc.skip_flags` (`--trust-all-tools`) | Only if the agent ran on a Linux host we could see; cloud API calls from a laptop are invisible |
| 2025-08-26 | s1ngularity (malicious Nx packages) runs `claude --dangerously-skip-permissions -p`, `gemini --yolo -p`, `q chat --trust-all-tools --no-interactive` to harvest secrets to `/tmp/inventory.txt` | developer machines and CI runners; auditd would have logged the argv | `proc.skip_flags` at weight 25 plus `proc.agent_name` 45: level `alert` on the first execve | CI runners rarely run auditd; laptops are out of scope |
| 2025-09 (report date; verify) | GTG-1002: threat actor uses Claude Code to run most of an intrusion campaign | targets saw SSH and tool traffic from agent-driven infrastructure | `rhythm.*` and `pty.none` on lateral SSH; `banner.library` if DEBUG1; `net.ai_api` only on hosts where the agent itself ran | attacker-controlled agents can be told to slow down and allocate PTYs |

Be explicit: in two of the four, whotyped on the affected host would not have seen the decisive action. The point is the pattern, not a claim that we would have stopped them.

## 4. What whotyped does

- Reads: sshd log (journald or file), auditd `audit.log`, `/proc`.
- Correlates: connection = `(user, ip, port)`; track = `(user, key fingerprint, ip)` over 15 minutes; joins auditd and `/proc` via `ses`/`sessionid`.
- Scores: seven clue categories with caps; alert at 70 requires two categories. Show the table from `ARCHITECTURE.md` §5.
- Outputs: `alerts.jsonl`, syslog, webhook (Slack/Teams), email, Prometheus. Sigma, Wazuh, Falco rules in `deploy/`.
- Worked example: the Claude Code Bash tool over SSH scores about 75 (rhythm 30, pty 15, style 30). The paramiko MCP server scores 88 with auditd, 70 without.

## 5. The declaration convention

Explain `AI_AGENT` over SSH in six sentences. One config line on the server. Snippets for OpenSSH and paramiko. The spoof-resistant `Match Group agents` + `SetEnv` variant. Link the spec and the PRs sent to MCP SSH servers.

## 6. Honest limits

Write this section first and do not soften it.

1. Evidence, not proof. A score is a sum of weak signals. Present it to a person, never to an automatic blocker.
2. Evasion is real. An agent told to allocate a PTY, wait 3 to 8 seconds between commands, avoid heredocs and never pass skip flags will score under 40. Keystroke-based detection has been shown to be forgeable (Stefan, Shu, Yao 2012; arXiv:2601.17280). We detect the default behaviour of today's tools, not a determined adversary.
3. Coverage depends on configuration. Without `LogLevel VERBOSE` we lose exec-channel counts. Without auditd we lose command style for remote agents. Without DEBUG1 we never see the client banner. `whotyped check` tells you what you have.
4. Library banners are shared with Ansible, Terraform and Teleport. Allowlist profiles exist for that reason; expect to tune for a week.
5. Vantage point. Only SSH into Linux hosts in v0.1. kubectl exec, docker exec and SSM sessions are documented but not detected yet.
6. Privacy. Default is redacted evidence, no command text. The HR/legal template exists because this is a monitoring tool and must be treated like one.
7. No telemetry, no phone home. That also means we do not know how many people run it.

## 7. Try it

Quickstart in five commands (link `docs/install/quickstart.md`). `whotyped simulate` produces a real alert through the real pipeline against localhost.

## 8. What we want from readers

False positives with the `reasons[]` block. Agents we have not fingerprinted (issue template). Maintainers of SSH tooling willing to send `AI_AGENT`. Pilots who will share anonymised counts.

## Checklist before publishing

- [ ] Every incident row checked against a primary source; dates corrected; "verify" markers removed
- [ ] Scores in §4 match the current `testdata/dataset` expectations
- [ ] Terminal recording is from a real run
- [ ] Links: spec, quickstart, compliance mapping, HR template, Sigma rules
- [ ] No usernames, hostnames or IPs from pilots
- [ ] Two reviewers signed off
