# Quickstart (5 minutes)

whotyped is one static binary plus a systemd unit. It needs root (to read `/var/log/audit/audit.log` and other users' `/proc/<pid>/environ`). Supported: Linux amd64 and arm64, systemd, OpenSSH 8.0 or newer. Tested distros for v0.1: Ubuntu 22.04/24.04, Debian 12/13, RHEL 9/10 and Rocky equivalents.

## 1. Install

Debian/Ubuntu:

```sh
curl -fsSLO https://github.com/whotyped/whotyped/releases/latest/download/whotyped_linux_amd64.deb
sudo dpkg -i whotyped_linux_amd64.deb
```

RHEL/Rocky/Fedora:

```sh
curl -fsSLO https://github.com/whotyped/whotyped/releases/latest/download/whotyped_linux_amd64.rpm
sudo rpm -i whotyped_linux_amd64.rpm
```

Plain binary (any distro):

```sh
curl -fsSLO https://github.com/whotyped/whotyped/releases/latest/download/whotyped_linux_amd64.tar.gz
tar xzf whotyped_linux_amd64.tar.gz
sudo install -m 0755 whotyped /usr/local/bin/whotyped
sudo install -d -m 0750 /etc/whotyped /var/lib/whotyped
sudo install -m 0640 deploy/config.example.yaml /etc/whotyped/config.yaml
sudo install -m 0644 deploy/whotyped.service /etc/systemd/system/whotyped.service
sudo systemctl daemon-reload
```

Replace `amd64` with `arm64` where needed. Release assets carry SHA-256 checksums signed with cosign (keyless); verify with `cosign verify-blob` if your policy requires it. Exact asset names are listed on the release page; adjust if they differ from the examples above.

## 2. Check the host and fix what is missing

```sh
sudo whotyped check
```

It reports, per reader, whether whotyped can see what it needs: sshd `LogLevel VERBOSE`, `AcceptEnv AI_AGENT`, the auditd `execve` rule, journald or auth.log access, `/proc` access. Exit 0 = full coverage, 1 = degraded (it will still run), 2 = cannot run.

To apply the recommended settings:

```sh
sudo whotyped check --fix
```

This writes three files and changes nothing else:

- `/etc/ssh/sshd_config.d/90-whotyped.conf`: `LogLevel VERBOSE` and `AcceptEnv AI_AGENT`.
- `/etc/ssh/sshrc`: the hook that logs `AI_AGENT` declarations, only if the host has no sshrc yet.
- `/etc/audit/rules.d/90-whotyped.rules`: the execve rule, from `deploy/audit.rules`.

It runs `sshd -t` but never reloads or restarts anything. Apply the changes yourself:

```sh
sudo systemctl reload ssh     # or: sudo systemctl reload sshd on RHEL, Fedora, SUSE
sudo augenrules --load
```

It does not enable `DEBUG1`; see `sshd-and-auditd.md` for why that is optional. Run `check` again afterwards and read the coverage line at the bottom.

## 3. Start it

```sh
sudo systemctl enable --now whotyped
sudo journalctl -u whotyped -n 20
```

Look for `readers: sshlog=journald auditd=file procfs=ok` (wording may differ slightly by version).

## 4. Prove it works

```sh
whotyped simulate --target "$USER@localhost"
```

`simulate` uses the system `ssh` to run 12 harmless, agent-shaped commands against localhost (no PTY, ControlMaster off) and then waits for whotyped to raise an alert about that session. Exit 0 means an alert at level `alert` or higher arrived. Exit 1 means the pipeline works but the score stayed under 70; run `whotyped check` and look at what is degraded. Exit 2 is a timeout, exit 3 means ssh itself failed (keys, `PasswordAuthentication`, firewall).

Offline, without touching sshd: `whotyped simulate --offline` replays fixture events through the real pipeline. Good for CI and for hosts where you cannot ssh to yourself.

## 5. Where alerts go

- File: `/var/lib/whotyped/alerts.jsonl`, one JSON object per line, schema `whotyped.alert.v1`. Rotated by size. `tail -f` it or ship it with your log agent.
- Summary: `whotyped report --since 7d` (tables) or `--format md` for a weekly email.
- Other sinks (syslog, webhook for Slack/Teams, email, Prometheus) are off by default; enable them in `/etc/whotyped/config.yaml` and see `integrations.md`.

A first alert looks like this (shortened):

```json
{"schema":"whotyped.alert.v1","ts":"2026-09-11T14:03:22Z","host":"web-03","event":"agent_detected",
 "class":"suspected_agent","mode":"remote_agent","user":"alice","src_ip":"10.0.0.5","score":82,"level":"alert",
 "reasons":[{"clue":"rhythm.burst","category":"rhythm","weight":20,"evidence":"14 exec channels in 92s"},
            {"clue":"pty.none","category":"pty","weight":15,"evidence":"0/14 sessions allocated a PTY"}],
 "session_id":"tr_9f31c2a7b8e4","actions_hint":"Ask alice whether an AI tool is driving this key."}
```

## 6. Tune

Expect a few false positives in the first week from Ansible, Terraform, VS Code Remote and backup scripts. Each alert lists its `reasons`; add an allowlist profile in the config for the user, source CIDR or key fingerprint and list the clue ids to suppress. Never suppress `process` or `flags` clues for a profile unless you really want agents allowed there. Details: FAQ and `deploy/config.example.yaml`.

## Uninstall

```sh
sudo systemctl disable --now whotyped
sudo apt remove whotyped   # or rpm -e whotyped
sudo rm -f /etc/ssh/sshd_config.d/*whotyped*.conf /etc/audit/rules.d/90-whotyped.rules
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
sudo augenrules --load
sudo rm -rf /var/lib/whotyped /etc/whotyped   # keeps nothing
```
