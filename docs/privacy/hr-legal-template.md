# whotyped: briefing template for HR, legal and works councils

Purpose: give the people who must approve a monitoring tool a complete, plain description of what whotyped collects, what it does not, who sees it and which settings change that. Copy it, fill the bracketed parts, delete what does not apply.

Deployment name: [ ]   Owner: [ ]   Contact: [ ]   Date: [ ]

## 1. What whotyped is

whotyped is a daemon on Linux servers. It reads the SSH server log, the Linux audit log and process metadata that the server already produces, and answers one question per SSH session: does this look like a human at a keyboard or like an AI software agent? It writes a short JSON record when it thinks an agent is present. It does not block anything.

The goal is accountability for AI agents, not surveillance of employees. The subject of the analysis is the session, and the outcome is "human" or "software". Human sessions produce no alert.

## 2. Data collected

Per alert, the following fields are written (schema `whotyped.alert.v1`):

| Field | Content | Personal data? |
|---|---|---|
| `ts`, `host` | time and server name | no |
| `event`, `class`, `mode`, `score`, `level` | the classification | no |
| `user` | the Linux account name of the session | yes, if accounts are personal |
| `src_ip` | the client IP address | yes (indirectly) |
| `key_fingerprint` | SHA-256 fingerprint of the SSH key used | yes (pseudonymous identifier) |
| `agent` | declared agent name (e.g. `claude-code`) if any | no |
| `reasons[].evidence` | short evidence strings, e.g. "14 exec channels in 92s", "0/14 sessions allocated a PTY", "argv0=claude flag=--dangerously-skip-permissions", "heredoc (len 212)" | see §3 |
| `session_id`, `connections`, `window` | internal correlation id and counts | no |
| `actions_hint` | fixed text suggesting what to do | no |

In memory only, for up to the scoring window (default 15 minutes) plus a short expiry, the daemon holds command start times, the first word of each command (`argv0`), command lengths, process names and the values of a fixed list of environment variables that name AI tools (`AI_AGENT`, `CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`, `CURSOR_AGENT`, `GOOSE_PROVIDER`, `COPILOT_MODEL` and similar). Full command text is held in memory when auditd is enabled, because the audit log contains it, but is not written out unless configured (§3).

Sources: `/var/log/auth.log` or journald (sshd lines), `/var/log/audit/audit.log` (if auditd is enabled), `/proc`. All of these exist and are already kept on the server independently of whotyped.

## 3. What is not collected

- No keystrokes, no keystroke timing, no terminal output.
- No full command lines by default. The default `privacy.command_text: redacted` writes only the matched fragment (e.g. the flag `--yolo`), the first word of the command and its length.
- No file contents, no network payloads.
- No screenshots, no webcam, no location.
- Nothing leaves the server unless a sink (syslog, webhook, email) is configured by the operator. The daemon makes no other network connections and sends no telemetry to the project.

## 4. Settings that change the data

| Setting | Default | Effect |
|---|---|---|
| `privacy.command_text` | `redacted` | `full` writes the complete command line into `evidence` (needed only for forensics; increases personal data). `none` writes no command-derived evidence at all. |
| `privacy.hash_usernames` | `false` | `true` replaces `user` with a keyed hash. Attribution then needs the key holder to reverse it. Suitable where the works council requires pseudonymisation at rest. |
| sshd `LogLevel DEBUG1` | not set | Optional. Reveals the SSH client software name (e.g. `OpenSSH_9.9`, `paramiko_3.4`). Also makes sshd log much more, including per-connection debug detail. Not recommended in the EU without a documented need. |
| auditd rule for `execve` | installed by `whotyped check --fix` | Makes command text available to the kernel audit log (root-readable) and therefore to whotyped's in-memory analysis. The audit log itself is a separate, pre-existing data store with its own retention. |
| Freeze windows | none | Named time windows in which any agent activity is reported at level `high`. No new data, only a different label. |
| Retention of `alerts.jsonl` | rotated by size (`sinks.jsonfile.max_size_mb: 50`, `keep: 5`) | Set to the shortest period that satisfies the audit purpose (suggest 90 days; PCI DSS asks for 12 months of audit logs with 3 months immediately available). |

The authoritative list of settings is `deploy/config.example.yaml`.

## 5. Who sees it

| Role | Access | Purpose |
|---|---|---|
| Server operations / SRE | `alerts.jsonl` on the host, SIEM dashboards | verify that unexpected agent activity is legitimate; stop it if not |
| Security operations | SIEM alerts at level `alert` and `high` | incident triage |
| Line managers | none by default | recommended: no access. whotyped data must not be used for performance assessment |
| HR | none | |
| Works council | on request: the weekly aggregate report, this document, the configuration file | verification that use matches the agreement |

Access to the raw file is governed by file permissions (`root:whotyped 0640`) and by the SIEM's role model. Fill in the actual groups: [ ].

## 6. Retention

- `alerts.jsonl`: [90 days], then deleted by rotation.
- SIEM copy: per the SIEM retention policy [ ].
- Weekly aggregate reports (no usernames when `hash_usernames: true`; no IPs): [12 months].
- In-memory session state: at most the scoring window plus expiry, typically under 30 minutes; `state.json` on disk holds open sessions across restarts and is overwritten every 30 seconds.

## 7. Lawful basis options (GDPR)

Pick one and record the reasoning:

- **Art. 6(1)(f) legitimate interest**: securing production systems and attributing automated actions to an accountable person. Balancing test: the processing analyses session behaviour, not content; humans produce no record; the alternative (full session recording) is more intrusive. Document the test.
- **Art. 6(1)(c) legal obligation** where a sector rule requires attribution of actions to individuals (PCI DSS is contractual, not a legal obligation; DORA and NIS2 transpositions may be; check with counsel).
- **Consent** is not a suitable basis for employee monitoring in most EU jurisdictions and is not recommended.

Data subjects: employees and contractors with SSH access. Special categories: none. Automated decision-making with legal effect (Art. 22): none; alerts are reviewed by people, and no action is taken automatically.

## 8. Germany and Austria specifics

- **BetrVG §87(1) Nr. 6**: a technical system that is objectively capable of monitoring employee behaviour or performance requires works-council co-determination, regardless of intent. whotyped qualifies. Conclude a Betriebsvereinbarung before rollout. Typical content: purpose limitation (agent detection and security incidents only), the list of fields above, the exclusion of performance assessment, access roles, retention, the works council's right to review the configuration, and the process for changing `privacy.*` settings.
- **BDSG §26 / GDPR Art. 88**: processing of employee data for the employment relationship must be necessary; a security purpose with data minimisation as configured here is the usual justification. Record it in the Verzeichnis von Verarbeitungstätigkeiten.
- **Austria ArbVG §96(1) Z 3**: control measures that affect human dignity require a Betriebsvereinbarung; §96a for personnel data systems. Same approach.

## 9. DPIA prompts

Answer these in the DPIA if one is required (Art. 35; systematic monitoring of employees is on most supervisory authorities' lists):

1. Which accounts are personal, which are shared or service accounts? Shared accounts change the attribution logic (`AI_AGENT_OPERATOR`).
2. Is `privacy.command_text` left at `redacted`? If `full` is needed, for which hosts and why?
3. Are usernames hashed at rest? Who holds the key?
4. Which sinks are configured, and does data leave the EU (e.g. a US-hosted SIEM or chat webhook)?
5. Who can change the configuration, and is the change logged?
6. How are false positives handled, and how does an employee contest a classification?
7. What is the retention and who verifies deletion?
8. Is `LogLevel DEBUG1` enabled anywhere? What extra data does sshd then log?
9. Is auditd used for other purposes on the same hosts, with its own retention?

## 10. Employee notice (draft paragraph)

> On our Linux servers we run a tool called whotyped. It looks at the pattern of SSH sessions (timing, whether a terminal was allocated, the names of processes and the first word of commands) to tell whether a session is being driven by an AI software agent instead of a person. It does not record what you type, your terminal output or, by default, your full commands. When it thinks an AI agent is using an account, it writes a short record with the account name, the client IP address, the SSH key fingerprint, the time and the reasons. Security and operations staff review these records to make sure AI tools on our servers are known and accountable. The records are not used to assess your performance. They are kept for [90 days]. If you use an AI tool over SSH, please let it identify itself by setting `AI_AGENT` (see [internal link]). Questions: [contact].

## 11. Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| System owner | | | |
| Data protection officer | | | |
| Works council | | | |
| Legal | | | |
