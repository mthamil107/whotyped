# sshd and auditd settings

What whotyped needs from the host, why, and what each setting costs. Source facts are from `docs/research/03-ssh-auditd-proc.md` (read from openssh-portable and Linux audit sources).

## sshd: LogLevel VERBOSE (recommended)

At the default `LogLevel INFO`, sshd logs `Accepted publickey for alice from IP port N ssh2: ED25519 SHA256:…` and disconnects. That gives whotyped the login, the key fingerprint and the source, but not how the session was used.

`VERBOSE` adds, per session channel:

```
Starting session: command for alice from 203.0.113.5 port 51234 id 0
Starting session: shell on pts/0 for alice from 203.0.113.5 port 51234 id 0
Close session: user alice from 203.0.113.5 port 51234 id 0
Connection from 203.0.113.5 port 51234 on 10.0.0.3 port 22
User child is on pid 3102
```

These lines are what the rhythm and PTY clues are built on: exec channels per minute, gaps between them, whether a PTY was ever allocated, and ControlMaster multiplexing (one TCP connection, many `Starting session` lines). Without VERBOSE, whotyped falls back to auditd execve timing for rhythm and loses the PTY clue for remote sessions.

Cost: a handful of extra lines per connection. No command text is ever logged (sshd deliberately logs `command` without the text). Failed public-key attempts also become visible at VERBOSE, which most people consider a benefit.

Drop-in file written by `whotyped check --fix`:

```
# /etc/ssh/sshd_config.d/50-whotyped.conf
LogLevel VERBOSE
AcceptEnv AI_AGENT AI_AGENT_*
```

`sshd_config.d` includes work when the main config has `Include /etc/ssh/sshd_config.d/*.conf` at the top (Ubuntu 22.04+, Debian 12+, RHEL 9+ do this). If a later `LogLevel` line exists in `sshd_config` itself, the first match wins in OpenSSH, so the drop-in must be included before it; `check` warns when the effective value (from `sshd -T`) is not VERBOSE.

## sshd: AcceptEnv AI_AGENT (recommended)

Lets a cooperative client declare itself (`docs/spec/ai-agent-over-ssh.md`). Without it sshd discards the variable silently. Zero privacy cost; the variable is set by the client and only says "I am an agent".

## sshd: LogLevel DEBUG1 (optional)

Only at DEBUG1 does sshd log the client software banner:

```
Remote protocol version 2.0, remote software version paramiko_3.4.0
```

(older wording: `Client protocol version 2.0; client software version …`). That line is the `banner.*` clue: `paramiko`, `AsyncSSH`, `ssh2js`, `Go`, `russh`, `libssh2` are strong library signals (weight 35), `OpenSSH_`, `PuTTY`, `WinSCP`, `MobaXterm` are human signals (-10).

Costs:

- Volume: DEBUG1 logs tens of lines per connection, including key exchange details, channel operations and, for every session, the environment variable names requested and other per-user details. On a busy bastion this is hundreds of MB per day.
- Privacy: the extra lines include client-side details (offered key types, requested env names) that a works council may consider profiling. `docs/privacy/hr-legal-template.md` treats DEBUG1 as an opt-in that needs a documented reason.
- Noise for other tools: fail2ban and log-based alerting may need re-tuning.

Recommendation: leave it off. Enable it on bastions and jump hosts only, where the extra signal is worth most, and set journald or logrotate limits. A passive banner capture (reading the first bytes of the TCP handshake) is planned so that DEBUG1 is not needed; it is not in v0.1.

## OpenSSH 9.8 and later: sshd-session

Since OpenSSH 9.8 the listener is `sshd` and each connection is handled by `sshd-session[pid]`; 10.0 adds `sshd-auth` for the pre-auth phase. Log lines therefore carry different syslog identifiers depending on version:

| OpenSSH | Identifiers seen |
|---|---|
| up to 9.7 (Ubuntu 22.04 8.9, 24.04 9.6, RHEL 9 8.7) | `sshd` |
| 9.8 to 9.9 (RHEL 10 9.9) | `sshd`, `sshd-session` |
| 10.0+ (Debian 13) | `sshd`, `sshd-session`, `sshd-auth` |

whotyped accepts all three and filters journald by `SYSLOG_IDENTIFIER`, not by unit name (Ubuntu's unit is `ssh.service`, RHEL's is `sshd.service`). If you ship logs to a SIEM, make sure your own filters do the same; the Sigma rules in `deploy/sigma/` do.

Process titles changed too (`sshd-session: alice@pts/0`), which matters for the `/proc` reader; handled.

## ControlMaster

OpenSSH multiplexing (`ControlMaster auto`, used by Ansible and many humans) opens one TCP connection and reuses it. Consequences:

- One `Accepted`, one `Connection from`, one PAM session open, but many `Starting session: … id N` lines. whotyped counts exec channels from `Starting session`, so rhythm still works.
- The process title grows: `sshd-session: alice@pts/0,pts/2`.
- Nothing distinguishes a multiplexed channel from a fresh one at the protocol level, and a human's `ssh` and their agent's `ssh` on the same laptop may share a ControlMaster socket. Then the session looks like one busy human. The key fingerprint and source IP are identical by construction. This is a known limit; the `AI_AGENT` declaration is the fix, since `SetEnv` is per channel.
- `whotyped simulate` disables ControlMaster for its own connections so that the test is honest.

## auditd

Rule installed by `check --fix` as `/etc/audit/rules.d/90-whotyped.rules` (source: `deploy/audit.rules`):

```
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k whotyped
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k whotyped
```

(`execveat` is rare on servers and not included by default; add `-S execve,execveat` if your workloads use it.)

Every command executed by a logged-in user (auid set by `pam_loginuid` in the sshd PAM stack) produces SYSCALL, EXECVE, CWD, PATH and PROCTITLE records sharing one `msg=audit(SECS.MSEC:SERIAL)` id, with `ses=` equal to the SSH session and `tty=pts0` or `tty=(none)`.

What it gives whotyped:

- Command style clues for remote agents (heredocs, compound commands, `bash -lc` wrappers, pager guards, absolute paths).
- Agent process names and skip flags even when the agent runs on the host (`claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`).
- A reliable join key (`ses`) between the SSH login and the commands.

What it costs:

- Once any syscall rule is loaded, the kernel evaluates the rule list on every syscall. Arch-first filtering keeps this cheap; expect low single-digit percent CPU on exec-heavy hosts (build servers) and nothing measurable on typical servers. UNVERIFIED as a number; measure on your own workload.
- Disk: 1 to 2 KB per exec. Set `max_log_file` and `num_logs` in `/etc/audit/auditd.conf`. Consider `-b 8192`, `-f 1` and `--backlog_wait_time 0` in your own rules file (they are not in `deploy/audit.rules`) so a burst never stalls processes.
- `/var/log/audit/audit.log` is root-only, so whotyped runs as root (or with group read access if you change the file mode; the systemd unit runs as root and drops nothing in v0.1).
- Only auditd may own the kernel audit socket. whotyped tails the file; it does not compete with auditd or with an existing audisp plugin.
- The audit log contains full command lines. whotyped keeps them in memory only for the scoring window and writes redacted evidence unless `privacy.command_text: full`.

Containers: auditd does not work inside Docker containers (no access to the kernel audit netlink socket from the container's namespace). Run whotyped on the host, not in the container. The Helm DaemonSet mounts the host's audit log for that reason.

Excluded on purpose: `kubectl exec`, `docker exec` and AWS SSM sessions have `auid=unset` and are dropped by the `-F auid!=unset` filter. They are documented in research doc 03 §7 and are a later phase.

## Checklist

```
sudo sshd -T | grep -Ei '^(loglevel|acceptenv|permituserenvironment)'
sudo auditctl -l | grep whotyped
sudo whotyped check
```
