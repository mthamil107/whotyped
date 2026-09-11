# Launch playbook

Nine moves, turned into tasks with owners and dates relative to launch day (T). Owner placeholders: `lead` (Thamil), `eng` (whichever engineer owns the feature), `pilot` (a pilot customer contact). Dates are targets; move them, but write down why.

Launch day T = the day the Show HN post goes up and v0.1.0 is tagged. Tuesday to Thursday, 14:00 to 16:00 UTC.

## Timeline

| When | Move | Task | Owner |
|---|---|---|---|
| T-6w | 1 Interviews | 15 interviews done, synthesis written (`docs/interviews/`) | lead |
| T-6w | 2 Pilot | 3 pilots signed (5 to 20 hosts each, 2 weeks), data-sharing agreed (anonymised counts only) | lead |
| T-5w | 3 Spec | `docs/spec/ai-agent-over-ssh.md` v0.1 published; PRs opened to 3 MCP SSH servers (paramiko, ssh2, asyncssh ones) using Appendix A | lead |
| T-4w | 2 Pilot | Pilots running; weekly `whotyped report` collected | pilot, eng |
| T-4w | 4 Integrations | Sigma rules pass `sigma check`; Wazuh rules loaded on a test manager; Falco rules loaded on a test node | eng |
| T-3w | 5 GIF | README GIF recorded (script below), 20 seconds, under 2 MB | eng |
| T-3w | 6 Data report | Pilot data report drafted from 2 weeks of data | lead |
| T-2w | 7 Posts | All post drafts reviewed by two people; claims checked against the code | lead |
| T-2w | 8 CFP | Abstract submitted to at least 2 conferences with open CFPs | lead |
| T-1w | 0 Release | v0.1.0-rc: deb/rpm/binaries signed, `whotyped simulate` green on Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10 (or Rocky) | eng |
| T-1w | 0 Release | SECURITY.md, CONTRIBUTING.md, issue templates live; 5 good-first-issues labelled | lead |
| T-2d | 7 Posts | Blog post final; screenshots; links tested | lead |
| T | Launch | Tag v0.1.0; Show HN; blog; LinkedIn; Lobsters | lead |
| T+1d | 7 Posts | r/sysadmin, r/devops (do not cross-post the same text) | lead |
| T+2d | 7 Posts | r/netsec (needs the technical angle; link to the blog, not the repo) | lead |
| T+3d | 9 Lists | Submit to awesome lists (below) | lead |
| T+1w | 6 Data report | Publish pilot data report as blog post 2 | lead |
| T+2w | 3 Spec | Follow up on MCP server PRs; publish adopter table | lead |
| T+4w | 2 Pilot | Second wave of pilots from launch inbound; v0.1.1 with false-positive fixes | eng |
| T+8w | 8 CFP | Talk delivered or recorded; slides in repo | lead |
| T+12w | Review | Targets table reviewed; decide v0.2 scope (eBPF, kubectl exec, SSM) | lead |

## Move 5: README GIF script

Use `asciinema rec` or `vhs`. Terminal 100x28, dark theme, 20 to 25 seconds, no typing pauses over 1 s. Commands in order:

```
$ whotyped version
whotyped v0.1.0 (linux/amd64)

$ sudo whotyped check
sshd  LogLevel VERBOSE        ok
sshd  AcceptEnv AI_AGENT      ok
auditd execve rule (whotyped) ok
procfs environ access         ok (root)
coverage: banner=no rhythm=yes pty=yes style=yes process=yes network=yes

$ sudo systemctl enable --now whotyped

$ whotyped simulate --scenario claude-bash --target localhost
running 12 agent-shaped commands over ssh (no pty, ControlMaster off) ...
waiting for alert ... 
ALERT agent_detected user=thamil src=127.0.0.1 score=76 level=alert
  rhythm.burst    +20  12 exec channels in 41s, median gap 2.1s
  pty.none        +15  0/12 sessions allocated a PTY
  style.tool_wrapper +8 bash -lc
  style.pager_guard +10 --no-pager, 2>&1
exit 0

$ tail -n1 /var/lib/whotyped/alerts.jsonl | jq .event,.user,.score
"agent_detected"
"thamil"
76
```

The numbers shown must be the numbers the tool actually printed on the recording machine. Re-record rather than edit.

## Move 6: pilot data report outline ("AI agents on our servers")

One page plus charts. All metrics anonymised: no hostnames, usernames, IPs or company names. Each pilot approves its own numbers before publication.

Metrics list:

1. Hosts monitored, days monitored, distro mix.
2. SSH sessions total; sessions classified `declared_agent`, `suspected_agent` (alert and high), `human`.
3. Share of agent sessions using a personal key vs a service account.
4. Mode split: `local_agent` (agent installed on the host) vs `remote_agent` (agent elsewhere driving SSH).
5. Which agents were declared (`AI_AGENT` values), which were guessed (rule ids).
6. Sessions with permission-skip flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`).
7. Median exec channels per agent session and median gap, vs human sessions.
8. Alerts per host per day at default thresholds; false-positive count after review; which allowlist profiles fixed them.
9. Freeze-window violations.
10. Time from alert to human acknowledgement (where a chat sink was used).
11. Coverage: percentage of hosts with auditd, with VERBOSE, with DEBUG1.

Structure: what we measured, what we found (3 to 5 findings with numbers), what surprised us, what we got wrong (false positives, missed agents), what changed in v0.1.1, how to reproduce on your own hosts.

## Move 7: post drafts

### Show HN

Title: `Show HN: Whotyped – tells you when an AI agent, not a human, is on your Linux server over SSH`

Body:

> I run servers and I could not answer a simple question: which of the SSH sessions on this box are people, and which are Claude Code or an MCP SSH server using someone's key? sshd does not log it, and no agent announces itself.
> whotyped is a small Go daemon that reads sshd logs, auditd and /proc, scores each session (exec-channel rhythm, no PTY, command style, agent process names and env vars, permission-skip flags, AI API connections) and writes a JSON alert with the reasons.
> It also proposes a one-line convention, `AcceptEnv AI_AGENT`, so cooperative agents can declare themselves; the draft spec and PRs to MCP SSH servers are in the repo.
> Honest limits: it is evidence, not proof. A careful agent can look human. It does not see command text unless you enable auditd, and it does not block anything.
> Apache-2.0, static binary, deb/rpm, Sigma/Wazuh/Falco rules included. `whotyped simulate` shows an alert in under a minute.
> I would like to hear what false positives you hit and which agent I have not fingerprinted yet.

### r/sysadmin

Angle: the shared-key problem, operational. Title: `Anyone else unable to tell which SSH sessions are AI agents? I wrote a daemon for it.` Body: 4 short paragraphs: the incident that started it (a colleague's key running 40 commands in 2 minutes at 2 a.m.; it was their Claude Code), what sshd does and does not log (VERBOSE gives you `Starting session: command`, DEBUG1 gives you the client banner), what the tool does in one paragraph, and a direct question: what would make you install another root daemon? Link to the quickstart, not the blog.

### r/devops

Angle: freeze windows and change control. Title: `We added "was an AI agent active during the freeze?" to our change process. Here is the open-source piece.` Body: describe `freeze_violation`, the Prometheus metrics, the Ansible role and Helm DaemonSet, and ask how others gate agent access in CI/CD.

### r/netsec

Angle: detection engineering. Title: `Detecting AI-agent-driven SSH sessions from the server side: signals, scoring and evasion` Link to the blog post. Comment with the scoring table, the s1ngularity argv patterns (`claude --dangerously-skip-permissions -p`, `gemini --yolo -p`, `q chat --trust-all-tools --no-interactive`), the Sigma rules, and the honest evasion section. Expect and welcome "this is evadable" replies; agree, cite arXiv:2601.17280, and point at the spoof-resistant `SetEnv` variant as the long-term answer.

### Lobsters

Tags: `security`, `linux`, `go`, `show`. Title: `whotyped: server-side detection of AI agents over SSH`. Text: 3 sentences plus the question "what would you want in a declaration convention for agents over SSH?" Lobsters readers care about the spec more than the product.

### LinkedIn

Angle: accountability and audit. 8 lines, no hashtags beyond three. "Auditors ask 'who ran this command?' PCI DSS 8.2.2 says every action must be attributable to an individual. When an AI agent uses a person's SSH key, the honest answer is 'we do not know'. I built an open-source daemon that answers it from the server side, with a compliance mapping and an HR briefing template for works councils. Link. What is your policy for AI agents on production hosts?"

## Move 8: conference CFP abstract (300 words)

Title: What whotyped would have shown: four AI-agent incidents replayed from the server's point of view

Abstract:

In 2025 and 2026 several incidents were caused or amplified by AI coding agents acting on infrastructure with human credentials. In July 2025 an agent on Replit deleted a production database during an explicit code freeze and then misreported what it had done. In 2025 the Kiro agent was tied to an AWS outage (details per public post-mortem; verify before the talk). The s1ngularity supply-chain attack against Nx in August 2025 invoked `claude --dangerously-skip-permissions`, `gemini --yolo` and `q chat --trust-all-tools` on developer machines to harvest secrets. GTG-1002 (Anthropic's September 2025 report) described a threat actor using Claude Code to run large parts of an intrusion campaign with minimal human input.

In each case the affected servers had sshd and, in some, auditd. Nobody was looking at those logs for the question "is this a person?"

This talk replays the four incidents through whotyped, an open-source Go daemon that classifies SSH sessions on the server as human, declared agent or suspected agent. For each incident we show the exact log lines that were available, which of whotyped's signals would have fired (exec-channel rhythm without a PTY, tool-wrapper command style, agent process names and environment variables, permission-skip flags, connections to AI API endpoints, activity inside a freeze window), the score it would have produced, and, honestly, what it would have missed.

We then cover the evasion problem: keystroke and timing detection is known to be defeatable, so we propose a cooperative convention, `AI_AGENT` over SSH `SetEnv`/`AcceptEnv`, with a spoof-resistant server-side variant using `Match` blocks and `authorized_keys` `environment=` options. We report on adoption by MCP SSH servers.

Attendees leave with the sshd and auditd settings that matter, four Sigma rules they can deploy the same day, and a compliance mapping to PCI DSS 8.2.2, ISO 27001 A.8.16 and OWASP Agentic ASI03/ASI10.

(Incident details marked "verify" must be checked against primary sources before submission; see `blog-post-draft.md`.)

Target CFPs: FOSDEM (security or containers devroom), BSides (local), SREcon EMEA, KubeCon (security track), Open Source Summit, CCC-adjacent regional events, OWASP Global AppSec.

## Move 9: awesome lists

Submit only after the README is stable and the repo has tests and a release.

- sindresorhus/awesome (via awesome-security or awesome-go entries, not directly)
- avelino/awesome-go (Security section; requires coverage badge and go report card)
- sbilly/awesome-security (Linux / auditing)
- fabacab/awesome-cybersecurity-blueteam (Detection / Linux)
- meirwah/awesome-incident-response (Linux evidence collection)
- SigmaHQ community rule contributions (the auditd rules, after a month of field use)
- Wazuh community rules repo
- falcosecurity/rules contrib (after testing)
- e-m-b-a/awesome-linux-security or equivalent (verify list is maintained)
- awesome-mcp-servers lists: not the tool itself, but the `AI_AGENT` spec as a recommendation for SSH servers

## Targets

| Metric | 90 days | 12 months | How measured |
|---|---|---|---|
| GitHub stars | 800 | 4,000 | GitHub |
| Distinct installs (no telemetry: count release asset downloads and package pulls) | 500 downloads | 5,000 downloads | GitHub release stats, package proxies |
| Pilots with shared data | 3 | 15 | signed pilot list |
| MCP SSH servers sending `AI_AGENT` | 2 merged PRs | 6 merged, plus one agent CLI shipping `SetEnv` guidance | PR tracker in spec appendix |
| Rule-pack contributions from outside the core team | 3 agents added | 15 | merged PRs with label `rule-pack` |
| False-positive issues open longer than 14 days | 0 | 0 | issue tracker query |
| Sigma rules accepted upstream | 0 (submitted) | 2 | SigmaHQ PRs |
| Talks | 1 accepted | 3 delivered | CFP tracker |
| Blog posts | 2 | 8 | repo `docs/launch/` |
| Security advisories handled within SLA | all | all | SECURITY.md process |

Review at T+12w and T+52w. If stars are far ahead of installs, the story is landing and the install path is not; fix the quickstart first.
