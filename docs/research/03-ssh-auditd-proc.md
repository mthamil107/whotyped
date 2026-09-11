# Linux source-of-truth notes: sshd, PAM, auditd, /proc (research, 2026-09-11)

Exact strings from openssh-portable, Linux, Linux-PAM, util-linux and tlog sources. UNVERIFIED marks anything not read from source. These formats drive the parsers.

## 1. OpenSSH server logging

**Syslog identifier.** Up to 9.7 every line is `sshd[PID]:`. 9.8 split into listener `sshd` plus per-connection `sshd-session`; 10.0 moved pre-auth into `sshd-auth`. Accept `SYSLOG_IDENTIFIER` in {sshd, sshd-session, sshd-auth}. Lines relayed through the monitor get a suffix ` [preauth]` or ` [postauth]`; strip it.

**Auth result** (`auth.c auth_log()`): `authmsg method[/submethod] for [invalid user ]USER from IP port N ssh2[: extra]`. Level is INFO when authenticated, invalid user, failures >= MaxAuthTries/2, or method password; otherwise VERBOSE. `Accepted` lines come from the privileged monitor and never carry `[preauth]`. `extra` is `KEYTYPE FINGERPRINT` (SHA256 by default) or for certificates `KEYTYPE-CERT FP ID <id> (serial N) CA KEYTYPE FP`.

```
Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:Q7kX...
Accepted publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519-CERT SHA256:Q7kX... ID alice@corp (serial 42) CA ED25519 SHA256:9mZ...
Accepted password for alice from 203.0.113.5 port 51234 ssh2
Accepted keyboard-interactive/pam for alice from 203.0.113.5 port 51234 ssh2
Failed password for invalid user admin from 198.51.100.9 port 40000 ssh2
Failed publickey for alice from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:...   (VERBOSE)
```

**Connection / session lines and levels**

| Line | Level |
|---|---|
| `Connection from IP port N on IP port 22[ rdomain "x"]` | VERBOSE |
| `User child is on pid N` | VERBOSE |
| `Starting session: <type>[ on pts/N] for USER from IP port N id K` | VERBOSE |
| `Close session: user USER from IP port N id K` | VERBOSE |
| `Received disconnect from IP port N:11: disconnected by user` | INFO (reason 11) |
| `Disconnected from user USER IP port N` | INFO |
| `Connection closed by authenticating user USER IP port N [preauth]` | INFO |
| `Connection closed by invalid user admin IP port N [preauth]` | INFO |
| `Connection reset by …`, `Connection from IP timed out` | INFO |
| `Timeout before authentication for IP, pid = N` | INFO |
| `Remote protocol version 2.0, remote software version paramiko_3.4.0` | DEBUG1 |
| old wording: `Client protocol version 2.0; client software version X` | DEBUG1 |

Session types: `shell`, `command` (command text is deliberately not logged), `subsystem 'sftp'`, `forced-command (config) '…'`, `forced-command (key-option) '…'`. A tty appears as ` on pts/N`. `id` is a session slot starting at 0, reused after close.

```
Starting session: shell on pts/0 for alice from 203.0.113.5 port 51234 id 0
Starting session: command for alice from 203.0.113.5 port 51234 id 0
Starting session: command on pts/1 for alice from 203.0.113.5 port 51234 id 1     (ssh -t host cmd)
Starting session: subsystem 'sftp' for alice from 203.0.113.5 port 51234 id 0
Starting session: forced-command (key-option) '/usr/local/bin/gate' for alice from 203.0.113.5 port 51234 id 0
Close session: user alice from 203.0.113.5 port 51234 id 0
```

**PAM line** (LOG_INFO, from the monitor PID): `pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)` and `session closed for user alice`. Older Linux-PAM (RHEL 8) lacks `(uid=N)`. Regex: `pam_unix\(sshd:session\): session opened for user (\S+?)(?:\(uid=(\d+)\))? by (\S*)\(uid=(\d+)\)`.

**Where.** Ubuntu 22.04 (8.9p1) and 24.04 (9.6p1): journald `_SYSTEMD_UNIT=ssh.service` (socket-activated); `/var/log/auth.log` only where rsyslog is installed. RHEL 8 (8.0p1) / 9 (8.7p1): `sshd.service`, rsyslog to `/var/log/secure`. RHEL 10 ships 9.9p1 and Debian 13 ships 10.0p1, so `sshd-session` identifiers. Filter journald by `SYSLOG_IDENTIFIER`, not unit name.

Syslog file line shape (rsyslog traditional): `Sep 11 14:03:22 web-03 sshd[1234]: Accepted publickey …`; RFC 3339 variants `2026-09-11T14:03:22.114532+00:00 web-03 sshd-session[1234]: …`. journalctl -o json fields: `MESSAGE`, `SYSLOG_IDENTIFIER`, `_PID`, `SYSLOG_PID`, `__REALTIME_TIMESTAMP` (microseconds as a string), `__CURSOR`.

## 2. AcceptEnv / SetEnv and environment

Client `ssh -o SetEnv=AI_AGENT=claude-code host` sends the variable; sshd copies it into the session environ only if `AcceptEnv AI_AGENT` is configured (default: accept none). Server logs only at DEBUG2: `Setting env N: AI_AGENT=claude-code`, `Ignoring env request AI_AGENT: disallowed name`, `Ignoring env request …: too many env vars` (cap 128).

Precedence in `do_setup_env()`, later wins: client env first, then USER/LOGNAME/HOME/PATH, authorized_keys `environment=` (needs PermitUserEnvironment), `~/.ssh/environment`, PAM env, then sshd_config `SetEnv`. So `Match Group agents` + `SetEnv AI_AGENT=…` or an authorized_keys `environment="AI_AGENT=claude-code"` overrides anything the client claims: a spoof-resistant declaration channel. Then `SSH_CLIENT="IP port serverport"`, `SSH_CONNECTION="IP port serverIP serverport"`, `SSH_TTY=/dev/pts/N` only with a pty, `SSH_ORIGINAL_COMMAND` only for forced commands. Visible in `/proc/PID/environ` of the shell and children (sudo `env_reset` drops it unless `env_keep += AI_AGENT`).

Session kinds: interactive gives `SSH_TTY`, `Starting session: shell on pts/N`, shell argv `-bash`. `ssh host cmd` gives no SSH_TTY, `Starting session: command for …`, shell argv `bash -c cmd`. `ssh -T host` gives `Starting session: shell for …` with no pts. `ssh -t host cmd` gives `command on pts/N`.

**PAM cannot see AI_AGENT.** `pam_open_session` runs in the monitor before the post-auth fork; channel `env` requests are processed later. A `pam_exec` session hook still yields `PAM_USER`, `PAM_RHOST`, `PAM_TTY=ssh`, PPID = monitor PID (the syslog PID that just received loginuid/sessionid).

## 3. auditd

```
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k whotyped
-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k whotyped
```
`unset` = `-1` = `4294967295`. x86_64 `arch=c000003e` execve=59 execveat=322; aarch64 `arch=c00000b7` execve=221 execveat=281.

One event = several records sharing `msg=audit(SECS.MSEC:SERIAL)`:
```
type=SYSCALL msg=audit(1757600000.123:4567): arch=c000003e syscall=59 success=yes exit=0 a0=55d0c1a3 a1=55d0c1b0 a2=55d0c2c0 a3=8 items=2 ppid=3055 pid=3102 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=7 comm="ls" exe="/usr/bin/ls" subj=unconfined key="whotyped"
type=EXECVE msg=audit(1757600000.123:4567): argc=3 a0="ls" a1="-la" a2=2F746D702F6D7920646972
type=CWD msg=audit(1757600000.123:4567): cwd="/home/alice"
type=PATH msg=audit(1757600000.123:4567): item=0 name="/usr/bin/ls" inode=… dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1757600000.123:4567): proctitle=6C73002D6C61002F746D702F6D7920646972
```
`tty=pts0` (no slash) or `tty=(none)`. With `log_format = ENRICHED` (RHEL 8+ default) each line gets a `0x1D` byte followed by `ARCH=x86_64 SYSCALL=execve AUID="alice" UID="alice" …`; split on `\x1d`.

**Hex rule.** A value is hex-encoded (uppercase, no prefix, whole value) if any byte is `"`, below 0x21 (space, controls) or above 0x7e; otherwise double-quoted. EXECVE args over 7500 bytes split as ` a1_len=N a1[0]=… a1[1]=…`. PROCTITLE is NUL-joined argv, hex whenever argc > 1; decode hex, split on NUL.

**ses/auid.** `pam_loginuid` in the sshd PAM session stack sets loginuid and the kernel assigns sessionid at the same time, in the monitor before the fork, so every process in the SSH session shares `ses`. Join keys: `/proc/PID/sessionid` of the sshd child, or the PAM-generated record:
```
type=USER_START msg=audit(1757600000.100:4560): pid=3055 uid=0 auid=1000 ses=7 subj=unconfined msg='op=PAM:session_open grantors=pam_loginuid,pam_keyinit,pam_limits,pam_systemd,pam_unix acct="alice" exe="/usr/sbin/sshd" hostname=203.0.113.5 addr=203.0.113.5 terminal=ssh res=success'
type=USER_LOGIN msg=audit(1757600000.101:4561): pid=3055 uid=0 auid=1000 ses=7 subj=unconfined msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=203.0.113.5 addr=203.0.113.5 terminal=/dev/pts/0 res=success'
type=USER_END msg=audit(1757600300.000:4700): pid=3055 uid=0 auid=1000 ses=7 subj=unconfined msg='op=PAM:session_close grantors=… acct="alice" exe="/usr/sbin/sshd" hostname=203.0.113.5 addr=203.0.113.5 terminal=ssh res=success'
```
No ports in these records; join to sshd log by pid + addr + time.

**Reading.** (a) `/var/log/audit/audit.log` (0600 root, size-rotated, `audit.log.1` …). (b) audisp `af_unix` plugin socket `/run/audit/audispd_events` (newline-delimited, same format). (c) `ausearch -k whotyped --start recent` for backfill. Only auditd may own the kernel audit netlink socket. **Cost:** once any syscall rule is loaded the matcher runs on every syscall; arch-first filtering keeps it cheap; each exec emits 5–7 records (1–2 KB). Set `-b 8192`, `-f 1`, `--backlog_wait_time 0`. **Env in audit is impossible**; read the session shell's `/proc/PID/environ` once and join by `ses`; eBPF `sys_enter_execve` envp in v1.0.

## 4. /proc parsing and the sshd process tree

`/proc/net/tcp` rows: whitespace-split gives `[1]=local`, `[2]=remote`, `[3]=st`, `[7]=uid`, `[9]=inode`. IPv4 is one `%08X` of the raw big-endian word, byte-reversed on little-endian hosts: `0100007F:0016` = 127.0.0.1:22; port is human order. IPv6 is four `%08X` groups each reversed independently: `::1` → `00000000000000000000000001000000`; `::ffff:127.0.0.1` → `0000000000000000FFFF00000100007F`. States: 01 ESTABLISHED, 02 SYN_SENT, 03 SYN_RECV, 04 FIN_WAIT1, 05 FIN_WAIT2, 06 TIME_WAIT, 07 CLOSE, 08 CLOSE_WAIT, 09 LAST_ACK, 0A LISTEN, 0B CLOSING. inode to pid: readlink `/proc/*/fd/*` for `socket:[INODE]`.

`/proc/PID/environ`, `cmdline`: NUL-separated; environ needs same uid or CAP_SYS_PTRACE; sshd's cmdline is the setproctitle string. `/proc/PID/status`: `Uid:\treal\teff\tsaved\tfs`, `PPid:\tN`, `NSpid:` with 2+ values means inside a pid namespace. `/proc/PID/stat`: split after the last `)`; field 22 `starttime` is index 19 of the tail; epoch = `btime` (from `/proc/stat`) + starttime/CLK_TCK (100). `/proc/PID/loginuid` and `/proc/PID/sessionid` give auid and ses (4294967295 = unset).

Process titles:
```
<=9.7    : sshd -D [listener] -> sshd: alice [priv] -> sshd: alice@pts/0 -> -bash -> cmd
9.8-10.4 : sshd -> sshd-session: alice [priv] -> sshd-session: alice@pts/0 -> -bash
>=10.5   : sshd -> sshd-session: alice [postauth] -> sshd-session: alice@pts/0,pts/2 -> -bash, -bash
regex: ^(sshd|sshd-session): (\S+) \[(priv|postauth)\]$
       ^(sshd|sshd-session): (\S+)@(notty|internal-sftp|pts/\d+(,pts/\d+)*)$
```
comm stays `sshd-session`; exe `/usr/lib/openssh/sshd-session` (Debian) or `/usr/libexec/openssh/sshd-session` (RHEL) (UNVERIFIED).

## 5. ControlMaster

One TCP connection gives one `Connection from`, one `Accepted`, one `User child is on pid`, one PAM open. Each multiplexed session is a new channel with its own `Starting session: … id N` / `Close session` pair, and the title grows to `alice@pts/0,pts/2`. Count sessions by `Starting session` (needs VERBOSE) keyed by (PID, id). Nothing distinguishes a mux slave from a fresh channel.

## 6. tlog and script

tlog JSON (ver 2.1): `host`, `rec`, `user`, `term`, `session` (= audit ses), `id`, `pos` (ms), `time`, `timing`, `in_txt`, `in_bin`, `out_txt`, `out_bin`. `timing` mini-language: `+N` delay ms, `<N` input chars, `[N/M` input bin, `>N` output chars, `]N/M` output bin, `=WxH` window. Example `=80x24<5+1>6+3>30+6>20` with `in_txt:"date\r"`. Journal fields `TLOG_REC`, `TLOG_USER`, `TLOG_SESSION`, `TLOG_ID`. Keystroke timing is available at per-read granularity: humans produce `<1+87<1+143…` runs; pasted or agent input arrives as one `<N` chunk. util-linux `script --log-timing`: `<delay> <bytes>` per output chunk.

## 7. Other entry paths (phase 2–3)

- **kubectl exec:** kubelet → CRI → `containerd-shim-runc-v2 -namespace k8s.io -id <sandbox>` → transient `runc exec`; the exec'd shell is reparented to the shim as a sibling of the container init. Detect: PPID is a shim/conmon, `NSpid` has 2+ entries with inner pid != 1, `/proc/PID/cgroup` contains `kubepods`. auid/ses are unset, so the audit rule above excludes it; add `-F auid=unset -F uid!=0` later.
- **docker exec:** same shape under `-namespace moby`. Reliable metadata is `docker events --filter event=exec_start`.
- **AWS SSM:** `amazon-ssm-agent` → `ssm-agent-worker` → `ssm-session-worker <session-id>` → `sh` as `ssm-user`. No PAM, so `auid=4294967295 ses=4294967295`; correlate by PPID chain and add a rule for `-F uid=<ssm-user>`.

## 8. eBPF for v1.0

cilium/ebpf (pure Go, bpf2go, CO-RE). Attach `tracepoint/sched/sched_process_exec` (read loginuid/sessionid from the task), `tracepoint/syscalls/sys_enter_execve` and `execveat` (argv, envp: capture AI_AGENT at exec), `tracepoint/sock/inet_sock_set_state` (server-side SSH = ESTABLISHED with sport 22; outbound to AI APIs), `kprobe/tcp_connect`, `sched_process_exit`. Needs BTF (Ubuntu 22.04+, RHEL 8.x backports UNVERIFIED per minor).

## 9. Privacy

Jurisdiction, not distro: Germany BetrVG §87(1) Nr. 6 (works-council co-determination over monitoring systems), GDPR Art. 88 as BDSG §26, Austria ArbVG §96. Default EU deployments to argv0, arg counts, timing and a keyed hash of the command, plaintext as explicit opt-in.

## Corrections to the plan's assumptions

1. The banner line is `Remote protocol version …` in current sshd (older: `Client protocol version …`) and is DEBUG1 in both cases.
2. `Accepted` lines never carry `[preauth]`.
3. PAM session open runs before env requests, so a PAM hook cannot see `AI_AGENT`.
4. SSM and container execs have unset auid/ses and are dropped by `-F auid!=unset`.
