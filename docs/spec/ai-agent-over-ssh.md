# AI_AGENT over SSH

**A one-variable convention that lets an SSH session say it is driven by an AI agent.**

Version 0.3 draft, 2026-09-22. Maintained in the [whotyped](https://github.com/mthamil107/whotyped) repository. Comments and corrections as issues, please. Free to implement, no permission needed, no attribution required.

"MUST", "SHOULD" and "MAY" carry their [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) meanings.

---

## The problem

An AI agent runs a command on a server over SSH, using a person's key. The server records the person. Anyone reading the logs later sees a name and has no way to know a model was at the keyboard.

Nothing in the SSH protocol says who is driving. Auditors ask "who ran this command", and the honest answer today is "we do not know".

This document defines the smallest possible way to answer: one environment variable, carried by a protocol request SSH has had since 2006, accepted with one line of server configuration.

It is cooperative by design. It lets honest tools identify themselves. It does not catch tools that stay quiet, and it is not meant to.

---

## Quick start

**If you run an AI coding tool**, your sessions can declare themselves today, without waiting for anyone. The major CLIs already set a marker in the shells they spawn, and OpenSSH can forward it:

```
# ~/.ssh/config on the machine where the agent runs
Host *
    SendEnv AI_AGENT AI_AGENT_* CLAUDECODE CURSOR_AGENT GEMINI_CLI CODEX_SANDBOX
```

```
# /etc/ssh/sshd_config on the server
AcceptEnv AI_AGENT AI_AGENT_* CLAUDECODE CURSOR_AGENT GEMINI_CLI CODEX_SANDBOX
```

A variable that is not set locally is not sent, so those lines stay silent for your own sessions and speak up for the agent's. `SendEnv` forwards a variable you already have; `SetEnv` writes a fixed value. For a declaration you want `SendEnv`.

**If you write a tool that opens SSH sessions**, send the variable yourself. One field on each call that opens a channel — count them before you start, because most projects have more than one:

```js
conn.exec(cmd, { env: { AI_AGENT: 'ssh-mcp' } }, cb);   // node ssh2
```

```python
client.exec_command(cmd, environment={"AI_AGENT": "my-mcp"})   # paramiko
```

**If you operate servers**, add the `AcceptEnv` line, then read the variable from the session environment. Section 4 lists the ways.

---

## 1. The variable

```
AI_AGENT=<name>
```

- **`<name>`**: lowercase ASCII letters, digits and hyphens, matching `^[a-z0-9]+(-[a-z0-9]+)*$`, at most 64 characters.
- Reuse the id an ecosystem already knows you by. Vercel's [detect-agent](https://github.com/vercel/detect-agent) `agents.json` is the de facto register: `claude-code`, `cursor-cli`, `codex-cli`, `gemini-cli`, `goose`, `github-copilot`.
- A tool that opens sessions on an agent's behalf and cannot learn the agent's name SHOULD send its own. Something truthful beats nothing.

### Versions: allowed, but not by default

A version MAY be appended as `<name>@<version>`, at most 32 further characters, no spaces.

Clients SHOULD NOT send a version to a host they do not control. As the first adopter put it: a name is an announcement, a version is a fingerprint. Tools of this kind exist to drive machines an agent was pointed at, and one of those machines being hostile is inside the threat model. Telling it the exact build is a gift.

Send the version when the fleet is yours and you want it in your own audit trail. Otherwise send the name.

### Optional companions

```
AI_AGENT_SESSION=<opaque id>      up to 128 printable ASCII characters, no spaces
AI_AGENT_OPERATOR=<human handle>  up to 128 characters, e.g. a username or email
```

`AI_AGENT_SESSION` lets an operator join what the server saw to the agent's own transcript. `AI_AGENT_OPERATOR` names the accountable human when the login is a shared or service account. Neither is required.

Clients MUST NOT put newlines, NUL bytes or shell metacharacters in any value. Servers and consumers SHOULD reject a value that breaks the grammar rather than sanitising it into something else.

---

## 2. The server side

```
# /etc/ssh/sshd_config.d/50-ai-agent.conf
AcceptEnv AI_AGENT AI_AGENT_*
```

Without it, OpenSSH ignores the request. The default is to accept nothing, and the refusal is logged only at `LogLevel DEBUG2`. Accepting these names is safe: they mean nothing to the shell or to any program that does not look for them.

### Making the declaration visible

An accepted variable lands in the session's environment. sshd does not log it at any normal log level, and a one-command session ends before any periodic scan could read it. If you want a record of every declaration, log it as the session starts:

```sh
# /etc/ssh/sshrc  (full version, with the xauth block sshd(8) requires:
#  https://github.com/mthamil107/whotyped/blob/main/deploy/sshd/sshrc)
if [ -n "${AI_AGENT:-}" ] && command -v logger >/dev/null 2>&1; then
	agent=$(printf '%s' "$AI_AGENT" | LC_ALL=C tr -cd 'A-Za-z0-9._@:+-' | cut -c1-64)
	set -- ${SSH_CONNECTION:-}
	[ -n "$agent" ] && [ -n "${1:-}" ] && logger -p authpriv.info -t ai-agent-declare -- \
		"AI_AGENT=$agent user=${USER:-$(id -un)} from=$1 port=$2" 2>/dev/null || :
fi
```

The tag is yours to choose; `ai-agent-declare` is the neutral one this document recommends. whotyped accepts it and also its own historical `whotyped-declare`.

sshd runs `/etc/ssh/sshrc` for every session, as the user, after the client's environment is in place and before the session's command runs. Two cautions: sshd skips it for a user who has their own `~/.ssh/rc`, and once this file exists sshd stops running `xauth` itself, so keep the `xauth` block from `sshd(8)` in it.

A line written this way is a claim any local user could also write with `logger`. A consumer MUST attach it only to an SSH connection that already exists for the same user, address and port, and SHOULD check journald's trusted `_UID` where available.

### When the client should not be believed

A client can claim anything. Two OpenSSH features let the server decide instead, both relying on environment precedence in `do_setup_env()`: client values first, then `authorized_keys` options, then `sshd_config` `SetEnv`, with later assignments winning.

Per group of agent accounts:

```
Match Group agents
    SetEnv AI_AGENT=unknown-agent
```

Per key, when an agent has its own key on a person's account:

```
# sshd_config
PermitUserEnvironment AI_AGENT,AI_AGENT_*
# ~/.ssh/authorized_keys
environment="AI_AGENT=claude-code" ssh-ed25519 AAAA... alice-agent-laptop
```

Enable only those names, never `PermitUserEnvironment yes`: a user-writable `environment=` for `LD_PRELOAD` or `PATH` is a known hazard. With either variant, a client that sends a different value is overridden, and one that sends nothing is still labelled. This is the form auditors want, because the label then depends on the credential rather than on good manners.

---

## 3. Sending it, by library

Every one of these produces the same `env` channel request from [RFC 4254 §6.4](https://www.rfc-editor.org/rfc/rfc4254#section-6.4). No SSH implementation needs changing.

| Client | Call |
|---|---|
| OpenSSH, per command | `ssh -o SendEnv=AI_AGENT host cmd` |
| OpenSSH, config | `SendEnv AI_AGENT` under a `Host` block |
| node ssh2 | `conn.exec(cmd, { env: { AI_AGENT: 'name' } }, cb)` |
| paramiko | `client.exec_command(cmd, environment={"AI_AGENT": "name"})` |
| paramiko, own channel | `chan.update_environment({"AI_AGENT": "name"})` |
| asyncssh | `await conn.run(cmd, env={"AI_AGENT": "name"})` |
| Go `x/crypto/ssh` | `session.Setenv("AI_AGENT", "name")` |
| russh | `channel.set_env(false, "AI_AGENT", "name").await` (unverified against current API) |

An unaccepted request cannot fail the command. ssh2, for example, sends it without asking for a reply, so the server has nothing to answer and nothing to refuse. This was measured by the first adopter against a server with no `AcceptEnv` line at all, and independently in whotyped's test lab against OpenSSH and Dropbear: the command runs, the variable is simply absent.

**`AcceptEnv` is not a gate on sending.** It is the server's policy about what it *passes into the session*, so it decides whether the value reaches the session environment — not whether the request reaches the host. Whenever the client is configured to send it — an ssh2 `env` option, or an OpenSSH `SendEnv` pattern matching a variable that is set locally — the request goes out regardless of what the server has configured, and a host that never opted in still receives it. Measured by the first adopter against Dropbear, which has no `AcceptEnv` mechanism at all:

```
Outbound: Sending CHANNEL_REQUEST (r:0, env: AI_AGENT=ssh-mcp)
Outbound: Sending CHANNEL_REQUEST (r:0, exec: echo hi)
```

So declaring is inert with respect to *breakage* and not with respect to *disclosure*. Every host a client talks to is told that an agent rather than a person is driving, whether or not it was configured to keep the value. That is the entire point of the convention, and toward a host the user does not control it is also a fact worth withholding: tools that feed command output back into a model have a threat model in which a hostile host tailors its output to inject the model, and knowing an agent is on the other end makes that attack worth attempting. Hence the switch in section 8.

---

## 4. Reading it, as an operator

- **Any process in the session.** It is in the environment of the session shell and everything it spawns; `/proc/<pid>/environ` shows it, with the same uid or `CAP_SYS_PTRACE`. It is *not* visible to PAM session hooks, because those run before the environment request is processed.
- **The sshrc hook above**, which gives you a log line per session, including one-command sessions.
- **Shell prompt or message of the day.** `[ -n "$AI_AGENT" ] && PS1="(agent:$AI_AGENT) $PS1"` makes it visible in session recordings.
- **sudo.** `env_reset` strips it; add `Defaults env_keep += "AI_AGENT AI_AGENT_SESSION AI_AGENT_OPERATOR"` to keep it across privileged commands.
- **whotyped**, the reference consumer, which reads both routes and labels the session `declared_agent`.

---

## 5. Security considerations

1. **A declaration is a statement, not proof.** It is exactly as trustworthy as the client. Log it, show it, correlate on it. Never use it for an authorization decision.
2. **Absence means nothing.** Most agents send nothing today. A missing variable is the normal case, not a negative signal. It becomes informative only when declaring is common, which is the point of the convention.
3. **Spoofing runs both ways.** A person can claim to be an agent to deflect blame; an agent passes as human by staying silent. The server-imposed variants in section 2 remove both, because the label then follows the credential.
4. **Injection.** Values reach shell environments and log lines. Enforce the grammar at the consumer, truncate, and strip control characters before writing evidence anywhere.
5. **Fingerprinting.** See the version guidance in section 1. The variable should say what is connecting, never which build, to a host you do not trust.
6. **Declaring is a disclosure, and `AcceptEnv` does not withhold it.** The request reaches every host the client is configured to send to, whether or not that host asked to keep the value (section 3). For a client whose command output returns to a model, telling an untrusted host that an agent is driving tells it that output-tailored prompt injection is worth attempting. Give users a switch, default on, and let them turn it off for hosts they do not control.
7. **Privacy.** `AI_AGENT_OPERATOR` names a person and is personal data, on the same footing as the SSH username.
8. **No secrets, ever.** These values end up in `/proc`, in session recordings and in SIEMs.

---

## 6. Relation to other conventions

- **Vercel detect-agent `AI_AGENT`.** Same variable, same grammar. detect-agent reads it inside the agent's own process; this document carries the same value across an SSH hop. A client that already runs inside an agent SHOULD forward the existing value unchanged rather than inventing one.
- **`AGENT=`.** Block's Goose sets a generic `AGENT` variable, and [agentsmd/agents.md#136](https://github.com/agentsmd/agents.md/issues/136) has been arguing since January 2026 about which name wins. This convention uses `AI_AGENT` because that is the name with a published registry and independent consumers behind it — Vercel's detect-agent, and the Firebase CLI, which checks `AI_AGENT` first and cites detect-agent for it. Not because `AGENT` is wrong: an earlier draft's claim that `AGENT` collides with unrelated software is withdrawn, because no concrete collision could be found. A client MAY map `AGENT` to `AI_AGENT` when the former is set and the latter is not, and a consumer MAY accept both. If the ecosystem settles on `AGENT`, this document will follow rather than fork.

  Whoever settles it should settle the *value* at the same time, because consumers already disagree. Bun's `is_ai_agent()` returns true only for `AGENT=1` and returns early, so `AGENT=goose` — the only value with a merged, public implementation behind it — reads as "not an agent" and also suppresses the `CLAUDECODE` check below it. A client that sends a name to a consumer expecting a boolean is worse off than one that sent nothing. `AI_AGENT` has the opposite problem in milder form: its value is always a name, so a consumer wanting a boolean must test for non-emptiness. This document takes the name form, and a consumer MUST NOT require a particular value: anything satisfying the grammar in section 1 is a declaration.
- **Per-vendor markers** (`CLAUDECODE`, `CODEX_SANDBOX`, `GEMINI_CLI`, `CURSOR_AGENT`, `GOOSE_PROVIDER`, `COPILOT_MODEL`). These identify the tool on the machine where it runs. They are not a substitute for `AI_AGENT`, but they are the bridge that works before anyone adopts anything: forward them with `SendEnv` as in the quick start, or use them to fill in `AI_AGENT` automatically when your client builds the request.

---

## 7. Who has adopted it

| Project | Status | Notes |
|---|---|---|
| [whotyped](https://github.com/mthamil107/whotyped) | reads it | Reference consumer: labels declared sessions, and scores the ones that stay silent |
| [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp) | sends it | Merged [#227](https://github.com/tufantunc/ssh-mcp/pull/227) on 2026-09-22. Name only, no version; `announceAgent` switch, default on. Declares on all three channel types |

Tools whose libraries expose the request and could adopt it cheaply, checked 2026-09-22:

| Project | Library | Activity |
|---|---|---|
| bvisible/mcp-ssh-manager | node ssh2 | active |
| Nightreaver/python-ssh-mcp | asyncssh | persistent shell, set once at open |
| chouzz/remoteShell-mcp | paramiko | small |
| RFingAdam/mcp-remote-access | paramiko | small |
| vignitin/multi-ssh-mcp | paramiko | small |

Two projects listed in the earlier draft are gone: the Go server that was here has been deleted from GitHub, and `VitalyMalakanov/mcp-ssh-toolkit-py` has not been touched since April 2025.

Send a pull request or open an issue to be added or corrected.

---

## 8. Adopting it, for tool maintainers

1. Pick your id: your tool's name, lowercase-hyphen.
2. If the process environment already has `AI_AGENT`, forward that value instead of your own.
3. Add the field at every place your code opens a channel — exec, shell and interactive are commonly three separate call sites. One line per call site, see section 3 and item 8.
4. Send the name only, unless your users are driving hosts they own.
5. Send `AI_AGENT_SESSION` if you have a session id worth correlating.
6. Do nothing about failures. There is no error path; an unaccepted name is ignored.
7. Offer a switch, default on. The announcement is the feature, so it should not be off by default — but a user connecting to a host they do not control has a reason to withhold it, and `AcceptEnv` will not withhold it for them. See section 3.
8. Add a test that fails if the field is removed, **for every channel your code opens**. Count them first: a project that opens a channel for `exec`, for a login shell and for an interactive session has three, and a suite that drives only the first will stay green with the feature deleted from the other two. Assert per call site, not per feature.
9. Document one line for your users: `AcceptEnv AI_AGENT AI_AGENT_*` on the server.
10. Never put a secret in the value.
11. Tell us, so the table above stays true.

### Questions adopters have asked

**Does this break connections to servers that have not configured it?** No. OpenSSH ignores an environment request it has not been told to accept, and the request does not ask for a reply, so there is nothing that can fail. Measured against OpenSSH without `AcceptEnv`, and against Dropbear, which has no `AcceptEnv` mechanism at all: the command runs and the variable is absent.

**Does a server that has not configured it still learn that an agent is connecting?** Yes. `AcceptEnv` controls what the server keeps, not what the client sends; the request arrives either way. Section 3 has the measurement. Treat "it cannot break anything" and "nobody finds out" as separate claims, because only the first is true.

**What about Dropbear, or Windows OpenSSH?** Both are measured. Dropbear: as above. Windows OpenSSH, measured by the first adopter on Windows 11 ARM against a macOS client — with no `AcceptEnv` line all sessions exit 0 and the variable is absent, with `AcceptEnv AI_AGENT` the value arrives on both the exec and pty paths while an unlisted name still does not. `AcceptEnv` is selective there rather than a blanket accept.

**Should it be configurable?** Yes, defaulting to on. The earlier advice here was that most projects would not need a switch, on the grounds that the value names only the tool. The first adopter overruled it with a better argument: a client that feeds command output back into a model has a threat model in which a hostile host tailors output to inject that model, so telling every host that an agent is driving is a disclosure the user may reasonably want to withhold — and `AcceptEnv` does not withhold it. Ship the switch on by default, so honest hosts still get the declaration.

**What does the server gain if nobody reads the variable?** A log line and a shell environment that say which tool connected. Any hook, audit rule or monitoring tool can read it. whotyped is one consumer, not a requirement.

---

## Appendix: pull request text

> **Declare agent sessions to the SSH server with `AI_AGENT`**
>
> This makes every SSH session this tool opens send the environment variable `AI_AGENT=<name>`, following the "AI_AGENT over SSH" convention: https://github.com/mthamil107/whotyped/blob/main/docs/spec/ai-agent-over-ssh.md
>
> **Why.** Operators increasingly need to tell agent-driven sessions from human ones, for audit reasons such as PCI DSS 8.2.2 and ISO 27001 A.8.16. Today a tool like this one looks like an anonymous library client on the server. Declaring is cheap and honest, and it means our sessions stop looking suspicious to anyone watching.
>
> **What it does.** One extra field on every channel this tool opens, using the library's existing API. If the server has not set `AcceptEnv AI_AGENT`, OpenSSH discards the value and nothing breaks — the request is sent without asking for a reply, so there is no error path. Note that unless the switch is off it is still *sent* to every host; `AcceptEnv` governs what the server keeps, not what the client transmits. The name only, no version, so a host that may be hostile is not told which build is talking to it.
>
> **Configurable.** On by default, with a switch for users driving hosts they do not control.
>
> **Tests.** One test per channel the code opens, each failing if that call site loses the field.

---

## Changes

- **v0.3 (2026-09-22).** Corrected after the first adopter merged and reviewed. `AcceptEnv` governs what a server passes into the session, not what a client sends, so declaring is inert with respect to breakage and not with respect to disclosure; the earlier text conflated the two, and section 5 now carries the consequence. A switch, default on, is recommended rather than discouraged. Windows OpenSSH measured. Adopters told to count their channel-opening call sites and test each one, after a patch that covered two of three. Section 6 withdraws the earlier claim that `AGENT` collides with unrelated software: no concrete collision could be found, and the real difference between the two names is that their values are read incompatibly today.
- **v0.2 (2026-09-22).** Quick start leading with `SendEnv`, which declares today's agent CLIs without vendor cooperation; corrected the earlier claim that OpenSSH cannot forward a local variable. Version discouraged toward untrusted hosts, after the first adopter's objection. Adopter questions and adopter table added. Compatibility table corrected: one project deleted upstream, one dead.
- **v0.1 (2026-09-11).** First draft.
