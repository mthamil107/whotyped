# Phase 0 lab

Goal: produce a labelled dataset of real SSH sessions, human and agent, on hosts configured the way we ask users to configure them. The dataset is the scorer's definition of done (`testdata/dataset/`), and the recordings are what we replay when a rule changes.

What we record per session:

- sshd log lines (journald JSON export) for `sshd`, `sshd-session`, `sshd-auth`
- auditd records for the session (`ausearch --raw` between start and end)
- `/proc` snapshots every 2 seconds: pid, ppid, uid, loginuid, sessionid, comm, exe, cmdline, and the values of the agent-related environment variables only
- `meta.json`: label, host, start, end, who ran it, notes

What we do not record: terminal output, keystrokes, or environment variables outside the agent list. Recordings from the lab can still contain real usernames and IPs; scrub before committing (`label.py --scrub`).

## Layout

```
lab/
  README.md                 this file
  cloud-init-ubuntu.yaml    Ubuntu 24.04 VM (multipass or any cloud)
  cloud-init-rocky.yaml     Rocky 9/10 VM
  docker-compose.yml        throwaway sshd container for quick tests (no auditd)
  Dockerfile.sshd
  record-session.sh         run on the lab host: captures one labelled recording
  scenarios.md              the 5 agents x 3 MCP servers x 5 humans matrix, with commands
  label.py                  recording dir -> events.jsonl + expected.json
  recordings/               output (gitignored except curated, scrubbed samples)
```

## Bring up a host

multipass (laptop):

```sh
multipass launch 24.04 --name lab-ubuntu --cpus 2 --memory 2G --disk 10G --cloud-init lab/cloud-init-ubuntu.yaml
multipass info lab-ubuntu     # note the IP
```

Rocky needs an image with cloud-init; on a cloud provider, paste `cloud-init-rocky.yaml` as user data. Before launching either, replace the `REPLACE_ME` public keys for `alice`, `bob` and `deploy`.

Then on your laptop add to `~/.ssh/config`:

```
Host lab
    HostName <ip>
    User alice
    IdentityFile ~/.ssh/lab_alice
    ControlMaster no
```

`ControlMaster no` matters: with multiplexing on, a human's shell and an agent's commands share one connection and the recording is ambiguous.

Install whotyped on the host too (quickstart), so each recording also has the daemon's own alerts in `/var/lib/whotyped/alerts.jsonl` for comparison.

## Record a session

On the lab host, as root:

```sh
sudo ./record-session.sh agent-claude-bash-01 600
```

This starts the `/proc` snapshot loop, waits 600 seconds (or until Ctrl-C), then exports the sshd journal and audit records for that window into `lab/recordings/agent-claude-bash-01-<ts>/`. While it waits, run the scenario from `scenarios.md` from your laptop. One scenario per recording; do not mix.

Label prefixes (the first token of the label sets the expected class in `label.py`):

| Prefix | Expected class | Expected score |
|---|---|---|
| `human-` | `human` | under 40 |
| `automation-` | `human` (after allowlist profile) | under 40 |
| `agent-` | `suspected_agent` | 70 or more |
| `declared-` | `declared_agent` | any (class wins) |
| `mixed-` | see `notes` | set manually in `expected.json` |

## Turn a recording into dataset files

```sh
python3 lab/label.py lab/recordings/agent-claude-bash-01-20260911T140000Z --scrub
```

Writes `events.jsonl` and `expected.json` into the recording directory. Copy both to `testdata/dataset/<label>/` when the recording is clean and reviewed (the dataset directory is owned by the scorer engineer; open a PR).

### events.jsonl format

One JSON object per line, sorted by `ts`, in the shape of `internal/event.Event`:

```json
{"ts":"2026-09-11T14:03:22.114532Z","kind":"ssh.auth_ok","source":"sshlog","user":"alice","src_ip":"203.0.113.5","src_port":51234,"pid":3055,"fields":{"method":"publickey","keytype":"ED25519","fp":"SHA256:Q7kX..."}}
{"ts":"2026-09-11T14:03:22.301000Z","kind":"ssh.session_start","source":"sshlog","user":"alice","src_ip":"203.0.113.5","src_port":51234,"pid":3055,"fields":{"stype":"command","tty":"","chan":"0"}}
{"ts":"2026-09-11T14:03:22.410000Z","kind":"audit.execve","source":"auditd","pid":3102,"ses":7,"fields":{"argv0":"bash","cmd":"bash -lc 'df -h'","exe":"/usr/bin/bash","comm":"bash","cwd":"/home/alice","tty":"(none)","uid":"1000","auid":"1000","ppid":3055}}
{"ts":"2026-09-11T14:03:24.000000Z","kind":"proc.seen","source":"procfs","pid":3102,"ses":7,"fields":{"comm":"bash","exe":"/usr/bin/bash","argv0":"bash","cmd":"bash -lc df -h","uid":"1000","loginuid":"1000","ppid":"3055","env.AI_AGENT":"claude-code"}}
```

Kinds and field keys are documented in `internal/event/event.go`. `label.py` emits: `ssh.auth_ok`, `ssh.auth_fail`, `ssh.banner`, `ssh.session_start`, `ssh.disconnect`, `ssh.pam_open`, `audit.login`, `audit.logout`, `audit.execve`, `proc.seen`. It does not emit `net.conn` (not captured in Phase 0) or `ssh.env` (sshd does not log it below DEBUG2).

### expected.json format

```json
{
  "label": "agent-claude-bash-01",
  "class": "suspected_agent",
  "min_score": 70,
  "max_score": 100,
  "user": "alice",
  "mode": "remote_agent",
  "must_have_clues": ["rhythm.burst", "pty.none"],
  "notes": "Claude Code Bash tool from laptop, 14 commands, no PTY",
  "recorded": "2026-09-11T14:00:00Z",
  "host_profile": {"distro": "ubuntu-24.04", "openssh": "9.6p1", "auditd": true, "loglevel": "VERBOSE"}
}
```

`label.py` fills `label`, `class`, `min_score`, `max_score`, `user`, `recorded` and `host_profile` from the recording; edit `mode`, `must_have_clues` and `notes` by hand. If the scorer team publishes a different schema in `testdata/dataset/README.md`, that one wins; update `label.py`.

## Ethics and privacy in the lab

Only lab hosts, only consenting participants (the five "humans" are team members or volunteers who sign the one-line consent in `scenarios.md`). Scrub usernames, IPs and key fingerprints before anything leaves the lab. Never point an agent at a host you do not own.
