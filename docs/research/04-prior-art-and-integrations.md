# Prior art, novelty verdict and integration formats (research, 2026-09-11)

## Verdict

**Novel as a product niche, incremental in technique. Build it.** Every individual signal is published somewhere (env-var conventions, process lineage, permission-skip flags, response timing, agent config dirs). Nobody combines them on the target Linux server, over SSH, passively, attributing to a human login, with SIEM-native outputs.

Lead with three differentiators:
1. **Vantage point is the server**, not the laptop and not an agent hook. Works when the agent is uncooperative, remote or unknown. Prempti, Defender and Falcon Guardian all stop at the developer endpoint.
2. **Identity attribution, not inventory.** "This session on alice's key behaves like an agent (score 82)" maps to PCI DSS 8.2.2 / 8.6.1, NIST AC-2(9), SOC 2 CC6.1.
3. **Boring, embeddable delivery.** Static Go binary, deb/rpm + systemd, JSON + Prometheus + Sigma/Wazuh/Falco rules.

## Closest prior work

| Work | What it does | Gap whotyped fills |
|---|---|---|
| Teleport Agentic Identity Framework (Jan 2026) | SPIFFE identities for enrolled agents, proxied and audited | Provisioning, not detection. Needs Teleport in the path. |
| Falco Prempti (May 2026, ~205 stars) | Intercepts Claude Code / Codex tool calls via PreToolUse hooks, Falco policy | Hook-cooperative, runs where the agent runs. Blind to an agent's bash tool sshing to a server. |
| Sysdig TRT (Mar 2026) | Syscall-level instrumentation of Claude Code / Gemini / Codex, four detection classes | Managed feed, endpoint focus, no SSH session classification. |
| AgentShield sigma-ai (16 stars) | Sigma rules over agent-emitted event logs (`product: ai_agent`) | Needs instrumented agents, no OS or SSH logsource. |
| Vercel detect-agent / `AI_AGENT` | Self-detection library; `AI_AGENT` first, then per-vendor vars | Gives us the declared class. No SSH-level declaration convention exists, which is the gap the AI_AGENT-over-SSH spec fills. |
| CrowdStrike Falcon Guardian (Sep 2026), Microsoft Defender local AI agent discovery, SentinelOne / Prompt Security, Sophos telemetry | Endpoint inventory and hooking of agents, Windows/macOS first | Laptop-centric, commercial, no "who is on prod-db-3 over SSH". |
| Elastic Security Labs (Aug 2026) | macOS Claude Code / Cursor tunnel and LaunchAgent rules | macOS only. |
| karmine05/agentic-detector (13 stars) | osquery extension inventorying agent CLIs and MCP servers | Installed-tool inventory, not live sessions. |
| ThirdKeyAI/agentsniff (10 stars) | Rust network sensor for LLM API DNS, MCP ports, bursty traffic | Network vantage, no login attribution. |
| cyberark/agentwatch (125 stars) | Python observability SDK for agent frameworks | In-process. |

Academic anchors: Song, Wagner, Tian (USENIX Security 2001) on SSH keystroke timing; Stefan, Shu, Yao (Computers & Security 2012) on synthetic keystroke forgeries; Reworr & Volkov, "LLM Agent Honeypot" (arXiv:2410.13919) found agents reply within ~1.7 s. Caveat: arXiv:2601.17280 argues keystroke-based AI authorship detection is evadable. Present scores as evidence, not proof.

## Integration formats

### Sigma
Required: `title`, `logsource`, `detection`; `id` UUIDv4; `status` experimental for new rules; `level`; `date` as YYYY-MM-DD; tags such as `attack.execution`, `attack.t1059.004`. Linux auditd rules use `type: 'EXECVE'` with `a0…aN`. Validate with `sigma check` (sigma-cli). No Wazuh backend exists, so ship native Wazuh XML. Correlation rules (`type: temporal`) exist in the v2 spec for "login followed by suspected agent".

### Wazuh
Read the JSON alert file with `<log_format>json</log_format>`; the built-in json decoder flattens fields. A custom decoder is only needed for syslog-wrapped lines (`<program_name>^whotyped$</program_name>` + `<plugin_decoder>JSON_Decoder</plugin_decoder>`). Custom rule IDs 100000–120000. Match numeric ranges with `type="pcre2"` regex because fields are strings.

### Falco
`proc.env[NAME]` exists (captured at exec); `proc.aname[N]` walks ancestors. Ship rules now, a source plugin later if wanted.

### Prometheus
Prefix `whotyped_`, `_total` on counters, no usernames or IPs as labels. `whotyped_sessions_total{class}`, `whotyped_active_sessions{class}`, `whotyped_alerts_total{level,sink}`, `whotyped_events_total{kind}`, `whotyped_events_dropped_total`, `whotyped_reader_up{name}`, `whotyped_build_info`.

### Supply chain
goreleaser v2 with `CGO_ENABLED=0`, linux amd64/arm64, `-trimpath`, syft SBOMs, cosign keyless bundle signing of checksums, nfpm deb/rpm with systemd unit and `config|noreplace` config. Provenance via GitHub artifact attestations (`actions/attest-build-provenance`) since slsa-github-generator is winding down (verify). OpenSSF Scorecard action on cron.

## Standards and regulation

- **OWASP Top 10 for Agentic Applications (2026, published 9 Dec 2025):** ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. whotyped maps to ASI03 and ASI10.
- **PCI DSS v4.0.1 Req 8:** 8.2.1 unique IDs; 8.2.2 shared accounts only by exception and all actions attributable to an individual; 8.6.1 interactive use of system accounts under the same conditions; 8.6.2 no hard-coded passwords; 8.6.3 rotation.
- **ISO/IEC 27001:2022:** A.8.15 Logging, A.8.16 Monitoring activities.
- **SOC 2:** CC6.1 logical access, CC7.2 anomaly monitoring.
- **NIST SP 800-53 r5:** AU-2, AU-3, AC-2, AC-2(9) shared and group accounts, AC-2(10).
- **EU AI Act Article 12 (record-keeping):** the Digital Omnibus on AI, Regulation (EU) 2026/1744 (OJ 24 Jul 2026, in force 27 Jul 2026), defers high-risk obligations to 2 Dec 2027 (Annex III) and 2 Aug 2028 (Annex I). whotyped is not itself a high-risk AI system. Position it as an evidence source for customers' logging duties, not as an Art. 12 compliance claim. Verify against the OJ text before quoting.
