# AI agent and MCP-SSH fingerprints (research, 2026-09-11)

Source-verified unless marked UNVERIFIED. Feeds `rules/*.yaml`.

## Claude Code (Anthropic)
- Process: `claude` (native binary) or `node` running the npm CLI; background supervisor `claude daemon`.
- Child-shell env: `CLAUDECODE=1` in every subprocess (documented stable marker); also `CLAUDE_CODE_CHILD_SESSION` (stdio MCP servers), `CLAUDE_PROJECT_DIR`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_SSE_PORT`. detect-agent matches `CLAUDECODE` or `CLAUDE_CODE`; Cowork adds `CLAUDE_CODE_IS_COWORK`. https://code.claude.com/docs/en/env-vars
- Skip flags: `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`. https://code.claude.com/docs/en/permission-modes
- Bash tool shape: absolute paths, avoid `cd`; chains with `;`/`&&`; no newlines; default timeout 120000 ms; commits via `git commit -m "$(cat <<'EOF' … EOF)"`; prefers `rg`. Commands arrive as `bash -c` children of `claude` with `CLAUDECODE=1`.
- Hosts: `api.anthropic.com`, `claude.ai`, `platform.claude.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, `http-intake.logs.us5.datadoghq.com`, `code.claude.com`. https://code.claude.com/docs/en/network-config
- User-Agent: `claude-cli/2.0.1 (external, cli)`.
- SSH: no built-in SSH tool. Claude Desktop "SSH sessions" install and run Claude Code on the remote host, so it appears as a local `claude` process under an SSH session.

## OpenAI Codex CLI
- Process: `codex` (Rust), helper `codex-linux-sandbox`; `codex exec` non-interactive.
- Child env: `CODEX_SANDBOX_NETWORK_DISABLED=1`, `CODEX_SANDBOX`; detect-agent also `CODEX_CI`, `CODEX_THREAD_ID`. https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/src/spawn.rs
- Flags: `--full-auto`, `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`), `--ask-for-approval never`, `--sandbox danger-full-access`.
- Hosts: `api.openai.com`, `chatgpt.com`.

## Gemini CLI
- Process: `gemini` (node); shell tool runs `bash -c` and sets `GEMINI_CLI=1`. https://google-gemini.github.io/gemini-cli/docs/tools/shell.html
- Flags: `--yolo`, `--approval-mode=yolo`.
- Hosts: `generativelanguage.googleapis.com` (API key), `cloudcode-pa.googleapis.com` (OAuth), `oauth2.googleapis.com`.

## Cursor
- CLI binary `cursor-agent` (newer: `agent`); flags `-p/--print`, `-f/--force` (alias `--yolo`), `--approve-mcps`, `--trust`; sets `CURSOR_AGENT=1` in shell commands; detect-agent: `CURSOR_AGENT`, `CURSOR_EXTENSION_HOST_ROLE=agent-exec`; IDE agent terminal: `CURSOR_TRACE_ID`. https://cursor.com/docs/cli/reference/parameters
- Remote-SSH: installs `~/.cursor-server` (not `~/.vscode-server`); remote process `~/.cursor-server/bin/<commit>/node …/out/server-main.js --start-server`, comm `cursor-server`. A remote server alone is a human-IDE signal; AI activity is the agent terminal beneath it.

## Aider
- Process `aider` (python); config env `AIDER_*` (input, not exported to children); `--yes-always`. Hosts via litellm; analytics `app.posthog.com`.

## Others
- OpenCode: `opencode`; env `OPENCODE`, `OPENCODE_CLIENT`.
- Goose (Block): `goose`; child env `GOOSE_TERMINAL=1`, `AGENT=goose`, `AGENT_SESSION_ID`, `GOOSE_PROVIDER`, `GOOSE_MODE=auto`. Note the generic `AGENT=goose`, a precedent for `AI_AGENT`.
- Amazon Q Developer CLI: `q`, `qchat`, `qterm`; `q chat --trust-all-tools --no-interactive`; shell-integration env `Q_TERM`, `QTERM_SESSION_ID`.
- Kiro CLI: `kiro-cli chat --no-interactive --trust-all-tools|--trust-tools=…`; `KIRO_API_KEY`; IDE `TERM_PROGRAM=kiro`. https://kiro.dev/docs/cli/headless/
- GitHub Copilot CLI: `copilot`; `--allow-all-tools`, `--allow-all`/`--yolo`; env `COPILOT_MODEL`, `COPILOT_ALLOW_ALL`, `COPILOT_GITHUB_TOKEN`.
- Devin: `/opt/.devin` file. Warp: `WARP_API_KEY` (child marker UNVERIFIED).

## Vercel detect-agent (`agents.json`)
`aiAgentVar: AI_AGENT` (value is the agent name, convention `claude-code`, `cursor-cli`, optional `@version`). Per-agent matches: cursor `CURSOR_TRACE_ID`; cursor-cli `CURSOR_AGENT` | `CURSOR_EXTENSION_HOST_ROLE=agent-exec`; kimi `KIMI_PLUGIN_ROOT`; grok `GROK_PLUGIN_ROOT|GROK_PLUGIN_DATA`; gemini_cli `GEMINI_CLI`; cline `CLINE_ACTIVE`; codex_cli `CODEX_SANDBOX|CODEX_CI|CODEX_THREAD_ID|CODEX_SANDBOX_NETWORK_DISABLED`; antigravity `ANTIGRAVITY_AGENT|ANTIGRAVITY_CLI_ALIAS`; augment-cli `AUGMENT_AGENT`; open_code `OPENCODE_CLIENT|OPENCODE`; goose `GOOSE_PROVIDER`; junie `JUNIE_DATA|JUNIE_SHIM_PATH`; cowork `CLAUDE_CODE_IS_COWORK`; claude_code `CLAUDECODE|CLAUDE_CODE`; replit `REPL_ID`; github-copilot `COPILOT_MODEL|COPILOT_ALLOW_ALL|COPILOT_GITHUB_TOKEN`; kiro `TERM_PROGRAM~kiro`; openclaw `OPENCLAW_SHELL`; devin `/opt/.devin`.
https://raw.githubusercontent.com/vercel/detect-agent/main/agents.json

## MCP SSH servers

| Server | Lang / lib | Client banner | Session model |
|---|---|---|---|
| tufantunc/ssh-mcp | Node, ssh2 ^1.17 | `SSH-2.0-ssh2js1.17.0` | exec-only `run-command` plus stateful `open-session` |
| bvisible/mcp-ssh-manager | Node, ssh2 | `SSH-2.0-ssh2js1.17.0` | pooled; wraps as `timeout N sh -c '…'` |
| VitalyMalakanov/mcp-ssh-toolkit-py, vignitin/multi-ssh-mcp, chouzz/remoteShell-mcp, RFingAdam/mcp-remote-access | Python, paramiko | `SSH-2.0-paramiko_3.x` | per-command or kept connections |
| Nightreaver/python-ssh-mcp | Python, asyncssh | `SSH-2.0-AsyncSSH_2.x` | persistent sentinel-based shell |
| SKIPPINGpetticoatconvent/go-ssh-mcp | Go, x/crypto/ssh | `SSH-2.0-Go` | pooled, PTY support |
| Brainwires/mcp-secure-shell | Rust | `SSH-2.0-russh_0.x` or `libssh2` (UNVERIFIED) | pooled |

None documents sending a custom env; paramiko `Channel.set_environment_variable` and asyncssh `env=` make `AI_AGENT` possible with `AcceptEnv AI_AGENT` server-side.

## SSH library banners (source-verified)
paramiko `SSH-2.0-paramiko_X.Y.Z`; asyncssh `SSH-2.0-AsyncSSH_X.Y.Z`; node ssh2 `SSH-2.0-ssh2jsX.Y.Z` (no underscore); Go `SSH-2.0-Go` (no version); russh `SSH-2.0-russh_0.xx`; libssh `SSH-2.0-libssh_X`; libssh2 `SSH-2.0-libssh2_X`; JSch `SSH-2.0-JSCH_X` (old: `JSCH-0.1.55`); sshj `SSH-2.0-SSHJ_X`; dropbear `SSH-2.0-dropbear_X`; PuTTY `SSH-2.0-PuTTY_Release_0.xx`; OpenSSH `SSH-2.0-OpenSSH_9.9p1 …`.

sshd log levels (openssh-portable): banner line `Remote protocol version %d.%d, remote software version %s` (older: `Client protocol version …; client software version …`) is `debug()` = LogLevel DEBUG1. `Accepted publickey … SHA256:…` is INFO. `Postponed publickey` and `Connection from IP port N on IP port 22` are VERBOSE.

## AI API hostnames
api.anthropic.com; api.openai.com, chatgpt.com; generativelanguage.googleapis.com, cloudcode-pa.googleapis.com, aiplatform.googleapis.com; bedrock-runtime.<region>.amazonaws.com; <resource>.openai.azure.com; api.cohere.com; api.mistral.ai; openrouter.ai; api.deepseek.com; api.fireworks.ai; api.groq.com; api.together.xyz; api.x.ai; api.perplexity.ai; Ollama 127.0.0.1:11434.

## Prior detection work
- AgentShield sigma-ai: 64 rules with `logsource product: ai_agent` consuming agent tool-call events, not OS telemetry; no rule on `--dangerously-skip-permissions`.
- Falco Prempti (May 2026): Falco plugin with a `coding_agent` event source fed by Claude Code hooks; needs agent cooperation. whotyped's gap: detection without cooperation.
- s1ngularity (Nx, 2025-08-26) invoked `claude --dangerously-skip-permissions -p`, `gemini --yolo -p`, `q chat --trust-all-tools --no-interactive`; wrote `/tmp/inventory.txt`. These three argv patterns are the highest-value process rules.

## Caveats for the rule packs
`SSH-2.0-Go` and paramiko banners are shared with Ansible, Terraform, Teleport. Treat as automation and require a second clue. Banner capture needs DEBUG1 or passive capture; auth fingerprints (INFO) and `Connection from` (VERBOSE) are cheap.
