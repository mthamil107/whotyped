# AI_AGENT over SSH — draft standard v0.1

Status: draft, 2026-09-11. Maintained in the whotyped repository. Comments as GitHub issues, please.

## 1. Purpose

Server operators need to know when an SSH session is driven by an AI agent rather than a person, even when the agent uses a person's key. Today there is no convention for an SSH client to say so. This document defines one. It is deliberately small: one environment variable, sent with the SSH protocol's existing `env` channel request, and accepted with one line of `sshd_config`.

The convention is cooperative. It lets well-behaved agents identify themselves. It does not detect agents that stay silent. Detection of silent agents is a separate problem (see the whotyped scorer); this spec only removes the excuse "there was no way to say it".

## 2. The convention

### 2.1 Client side

An SSH client acting on behalf of an AI agent SHOULD request the environment variable `AI_AGENT` on every session channel it opens (shell, exec or subsystem).

```
AI_AGENT=<name>[@<version>]
```

- `<name>`: lowercase ASCII letters, digits and hyphens, matching `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 64 characters. This is the grammar used by Vercel detect-agent's `agents.json` (`claude-code`, `cursor-cli`, `codex-cli`, `gemini-cli`, `goose`, `github-copilot`). Reuse an existing detect-agent id where one exists: https://raw.githubusercontent.com/vercel/detect-agent/main/agents.json
- `<version>`: optional, free-form after `@`, no spaces, at most 32 characters. Example: `claude-code@2.0.1`.
- An MCP server or other intermediary that opens SSH sessions for an agent SHOULD send its own name if it cannot learn the agent's, e.g. `AI_AGENT=ssh-mcp@1.2.0`. Something truthful beats nothing.

Two optional variables MAY be sent alongside:

```
AI_AGENT_SESSION=<opaque id>      up to 128 chars, printable ASCII, no spaces
AI_AGENT_OPERATOR=<human handle>  up to 128 chars, e.g. an email or username
```

`AI_AGENT_SESSION` lets an operator join server-side evidence to the agent's own transcript. `AI_AGENT_OPERATOR` names the accountable human when the SSH login is a shared or service account. Neither is required.

Clients MUST NOT put newlines, NUL bytes or shell metacharacters in any of these values. Servers SHOULD drop values that violate the grammar rather than sanitising them.

### 2.2 Server side

The server accepts the declaration with:

```
# /etc/ssh/sshd_config.d/50-ai-agent.conf
AcceptEnv AI_AGENT AI_AGENT_*
```

Without `AcceptEnv`, OpenSSH silently discards the request (the default is to accept nothing; the discard is logged only at DEBUG2 as `Ignoring env request AI_AGENT: disallowed name`). Accepting these names is safe: they carry no meaning to the shell or to any known program.

### 2.3 Spoof-resistant variants

A client can claim anything. Two OpenSSH features let the server impose the value instead. Both rely on the environment precedence in OpenSSH's `do_setup_env()`: client variables are applied first, then `authorized_keys` `environment=` options, then `sshd_config` `SetEnv`, and later assignments win (see `docs/research/03-ssh-auditd-proc.md` §2).

Per group of agent accounts:

```
Match Group agents
    SetEnv AI_AGENT=unknown-agent
    # optionally: ForceCommand, PermitTTY no, etc.
```

Per key, when an agent has its own key on a human's account:

```
# sshd_config
PermitUserEnvironment AI_AGENT,AI_AGENT_*
# ~/.ssh/authorized_keys
environment="AI_AGENT=claude-code",environment="AI_AGENT_OPERATOR=alice" ssh-ed25519 AAAA... alice-claude-laptop
```

`PermitUserEnvironment` accepts a pattern list of variable names (OpenSSH 7.8 and later; UNVERIFIED for the exact first version). Enable only these names, never `yes`, because a user-writable `environment=` for `LD_PRELOAD` or `PATH` is a known hazard. With either variant, a client that sends `AI_AGENT=` with a different value is overridden, and one that sends nothing is still labelled.

## 3. How consumers read it

- **Any process in the session.** The variable is in the environment of the session shell and everything it spawns. `/proc/<pid>/environ` (same uid or `CAP_SYS_PTRACE`) shows it. It is not visible to PAM session hooks: `pam_open_session` runs before the channel `env` request is processed (research doc 03 §2).
- **whotyped.** The procfs reader reads the environ of each SSH session shell, joins it to the sshd connection by `/proc/<pid>/sessionid`, and emits `class=declared_agent`, `agent=<name>` at level `info`. Declared agents are reported, not alerted on, unless a freeze window is active.
- **Shell prompts and MOTD.** `[ -n "$AI_AGENT" ] && PS1="(agent:$AI_AGENT) $PS1"` in `/etc/profile.d/`. Cheap and visible in session recordings.
- **sudo.** `env_reset` strips it. Add `Defaults env_keep += "AI_AGENT AI_AGENT_SESSION AI_AGENT_OPERATOR"` so it survives into privileged commands.
- **Session recorders.** tlog and `script` do not record the environment; capture it once at shell start, e.g. `/etc/profile.d/ai-agent-log.sh` running `logger -t ai_agent "user=$USER agent=${AI_AGENT:-none} session=${AI_AGENT_SESSION:-} operator=${AI_AGENT_OPERATOR:-}"`.

## 4. How clients set it

OpenSSH command line:

```sh
ssh -o SetEnv=AI_AGENT=claude-code@2.0.1 -o SetEnv=AI_AGENT_OPERATOR=alice host cmd
```

or in `~/.ssh/config`: `SetEnv AI_AGENT=claude-code`. (`SetEnv` exists since OpenSSH 7.8.)

paramiko:

```python
stdin, stdout, stderr = client.exec_command(cmd, environment={"AI_AGENT": "my-mcp@0.3.0"})
# or on a channel you manage yourself:
chan = client.get_transport().open_session()
chan.update_environment({"AI_AGENT": "my-mcp@0.3.0", "AI_AGENT_SESSION": sid})
chan.exec_command(cmd)
```

asyncssh:

```python
result = await conn.run(cmd, env={"AI_AGENT": "my-mcp@0.3.0"})
```

node ssh2:

```js
conn.exec(cmd, { env: { AI_AGENT: "ssh-mcp@1.2.0", AI_AGENT_SESSION: sid } }, cb);
```

Go `golang.org/x/crypto/ssh`:

```go
sess, _ := client.NewSession()
_ = sess.Setenv("AI_AGENT", "go-ssh-mcp@0.1.0") // silently ignored unless AcceptEnv matches
out, err := sess.CombinedOutput(cmd)
```

Rust russh: `channel.set_env(false, "AI_AGENT", "value").await` (UNVERIFIED against the current russh API).

All of these send the same protocol request (`env`, RFC 4254 §6.4), so nothing new is needed in any SSH implementation.

## 5. Security considerations

1. **A declaration is a statement, not proof.** It is exactly as trustworthy as the client. Log it, display it, correlate on it. Never use it for authorization decisions, and never treat its absence as evidence that a human is present.
2. **Absence means nothing.** Most agents today send nothing. A missing `AI_AGENT` is the normal case, not a negative signal.
3. **Spoofing in both directions.** A human can claim to be an agent (to deflect blame) and an agent can pass as human by staying silent. The server-imposed variants in §2.3 make the label depend on the credential, which is the property auditors actually want.
4. **Injection.** Values reach shell environments and log lines. Enforce the grammar on the server or in the consumer. whotyped truncates and strips control characters before writing evidence.
5. **Privacy.** `AI_AGENT_OPERATOR` names a person. Treat it as personal data under the same rules as the SSH username.
6. **No secrets.** Never put API keys or tokens in these variables. They end up in `/proc/*/environ`, session recordings and SIEMs.

## 6. Relation to other conventions

- **Vercel detect-agent `AI_AGENT`.** Same variable, same value grammar. detect-agent reads it in the agent's own process environment; this spec carries the same value across an SSH hop so the remote side sees it too. A client that already runs inside an agent SHOULD forward the existing local `AI_AGENT` value unchanged.
- **Goose `AGENT=goose`.** Block's Goose sets a generic `AGENT` variable plus `AGENT_SESSION_ID` (research doc 02). Clients MAY map `AGENT` to `AI_AGENT` when the former is set and the latter is not. Servers should accept `AGENT` only deliberately; it is a common word and collides with other software.
- **Per-vendor variables** (`CLAUDECODE=1`, `CODEX_SANDBOX`, `GEMINI_CLI=1`, `CURSOR_AGENT=1`, `GOOSE_PROVIDER`, `COPILOT_MODEL`, …) identify the agent on the machine where it runs. They are not sent over SSH and are not a substitute for `AI_AGENT`. A client library can use them to fill in `AI_AGENT` automatically: if `CLAUDECODE` is set and `AI_AGENT` is not, send `AI_AGENT=claude-code`.

## 7. MCP SSH servers: compatibility

From `docs/research/02-agent-fingerprints.md`. "Could adopt" means the underlying library exposes the `env` request; none of these servers send it today (checked 2026-09-11; none documents a custom env).

| Server | Library | Env request available | Could adopt | Notes |
|---|---|---|---|---|
| tufantunc/ssh-mcp | node ssh2 | `exec(cmd, {env})`, `shell({env})` | yes | banner `SSH-2.0-ssh2js…` |
| bvisible/mcp-ssh-manager | node ssh2 | same | yes | wraps commands as `timeout N sh -c` |
| VitalyMalakanov/mcp-ssh-toolkit-py | paramiko | `exec_command(environment=)` | yes | |
| vignitin/multi-ssh-mcp | paramiko | same | yes | |
| chouzz/remoteShell-mcp | paramiko | same | yes | |
| RFingAdam/mcp-remote-access | paramiko | same | yes | |
| Nightreaver/python-ssh-mcp | asyncssh | `env=` on `run`/`create_process` | yes | persistent shell: set once at open |
| SKIPPINGpetticoatconvent/go-ssh-mcp | x/crypto/ssh | `Session.Setenv` | yes | |
| Brainwires/mcp-secure-shell | russh or libssh2 (UNVERIFIED) | russh `set_env`; libssh2 `libssh2_channel_setenv` | probably | library not confirmed |

The agent CLIs themselves (Claude Code, Codex, Gemini CLI, Cursor CLI, Goose, Copilot CLI) have no built-in SSH tool; they call the system `ssh`. For them the fix is one line in the user's `~/.ssh/config`, or a wrapper that passes `-o SetEnv=AI_AGENT=...`. OpenSSH has no "forward this local variable" option for `SetEnv`, so the value must be written into the config or supplied on the command line.

## 8. How to adopt in 10 lines (MCP server maintainers)

1. Pick your id: your server's name in lowercase-hyphen, plus version. Example `ssh-mcp@1.3.0`.
2. If the process environment already has `AI_AGENT`, forward that value instead of your own.
3. Add the variable to every session you open (see §4 for your library's call).
4. If you know a session id, send `AI_AGENT_SESSION`. If you know the human, send `AI_AGENT_OPERATOR`.
5. Do nothing if the server ignores it. There is no error path.
6. Document one line for operators: `AcceptEnv AI_AGENT AI_AGENT_*`.
7. Add a config switch to turn it off; default on.
8. Do not put secrets in the value.
9. Add a test that asserts the env request is sent (paramiko: mock `update_environment`; ssh2: assert `env` in exec options).
10. Tell us (issue in this repo) so the compatibility table gets updated.

## Appendix A: PR text for maintainers

Title: `Declare AI agent sessions to the SSH server via AI_AGENT env`

Body:

> This change makes every SSH session opened by this server request the environment variable `AI_AGENT=<name>@<version>` (and `AI_AGENT_SESSION` where a session id is known). It follows the draft "AI_AGENT over SSH" convention: https://github.com/whotyped/whotyped/blob/main/docs/spec/ai-agent-over-ssh.md
>
> Why: operators of Linux servers increasingly need to tell agent-driven sessions from human ones for audit reasons (PCI DSS 8.2.2, ISO 27001 A.8.16). Today an MCP SSH server looks like an anonymous library client. Declaring the agent is cheap and honest.
>
> What it does: one extra `env` channel request per session, using the library's existing API. If the server has not configured `AcceptEnv AI_AGENT AI_AGENT_*`, OpenSSH ignores it silently. There is no behaviour change for users. The value uses the same grammar as Vercel's detect-agent `AI_AGENT` variable and forwards a pre-existing `AI_AGENT` from the process environment when present.
>
> Config: `declare_agent: true` (default). Set to `false` to disable.
>
> Tests: added a unit test asserting the env request is sent.

## Appendix B: Changes

- v0.1 (2026-09-11): first draft.
