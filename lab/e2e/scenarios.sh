#!/bin/bash
# Runs inside the lab container and asserts what whotyped reported.
#   Pass A: a default install (LogLevel VERBOSE, sshrc hook, no auditd).
#   Pass B: LogLevel DEBUG1 (client banners) with an active freeze window.
# Each scenario uses its own Unix user so the tracks never mix. Exit status is
# non-zero when any expectation fails.
set -u
PASS="${1:-A}"
ALERTS=/var/lib/whotyped/alerts.jsonl
H=127.0.0.1
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ControlMaster=no -i /root/.ssh/id_ed25519"
note() { printf '\n=== %s ===\n' "$*"; }
quiet_sim() { whotyped simulate "$@" 2>&1 | grep -E '^(alert|no alert|an alert|clue families|  likely|waiting)'; }

sleep 3 # let the daemon open its readers

if [ "$PASS" = "A" ]; then
  note "alice: agent-shaped one-command-per-step session (OpenSSH client, no declaration)"
  quiet_sim --target alice@$H --scenario claude-bash --timeout 60s --alerts $ALERTS

  note "bob: human-shaped PTY session"
  quiet_sim --target bob@$H --scenario human --timeout 40s --alerts $ALERTS

  note "carol: declared agent, SetEnv AI_AGENT on every one-command session"
  quiet_sim --target carol@$H --scenario claude-bash --declared --timeout 60s --alerts $ALERTS

  note "dave: paramiko client, one transport, 10 exec channels (MCP SSH server shape)"
  python3 /usr/local/bin/paramiko_client.py dave $H /root/.ssh/id_ed25519 10

  note "erin: agent process on the box: claude --dangerously-skip-permissions with CLAUDECODE=1"
  $SSH erin@$H 'CLAUDECODE=1 FAKE_CLAUDE_SECONDS=40 ~/bin/claude --dangerously-skip-permissions -p "list the logs"'

  note "frank: ssh -tt on every command, plus a spoofed AI_AGENT=human background process"
  su frank -c 'AI_AGENT=human nohup sleep 120 >/dev/null 2>&1 &'
  for c in 'cd /tmp && ls -la 2>&1 | head -n 20' 'uname -a' 'df -h / 2>&1 | tail -n 1' \
           'ps aux | head -n 5' 'id' 'uptime' 'free -m' 'sed -n "1,5p" /etc/passwd'; do
    $SSH -tt frank@$H "$c" >/dev/null 2>&1
    sleep 0.6
  done

  note "sshrc hook must not consume a command's stdin"
  got=$(printf 'payload-through-stdin\n' | $SSH -o SetEnv=AI_AGENT=stdin-check grace@$H 'cat')
  echo "$got" > /var/lib/whotyped/stdin-check.txt
  echo "received: $got"

  note "forged declaration for a session that does not exist"
  su frank -c 'logger -p authpriv.info -t whotyped-declare -- "AI_AGENT=forged user=bob from=127.0.0.1 port=1"'
else
  note "dave: paramiko client with LogLevel DEBUG1 (banner visible) during a freeze window"
  python3 /usr/local/bin/paramiko_client.py dave $H /root/.ssh/id_ed25519 12

  note "carol: declared agent during the freeze window"
  quiet_sim --target carol@$H --scenario claude-bash --declared --timeout 60s --alerts $ALERTS

  note "bob: a human logging in during the freeze window (should stay quiet)"
  quiet_sim --target bob@$H --scenario human --timeout 30s --alerts $ALERTS
fi

sleep 8 # two procfs scans and a scoring pass after the last event

note "whotyped check after traffic"
whotyped check --config /etc/whotyped/config.yaml 2>&1 | grep -E 'sshd.sshrc|sshlog.content|coverage.identity|coverage.style|^result'

note "metrics endpoint"
python3 - <<'PY'
import urllib.request
body = urllib.request.urlopen("http://127.0.0.1:9477/metrics", timeout=5).read().decode()
for line in body.splitlines():
    if line.startswith(("whotyped_alerts_total", "whotyped_tracks_open", "whotyped_events_total")):
        print(line)
PY

note "assertions"
python3 - "$ALERTS" "$PASS" <<'PY'
import json, sys

path, pas = sys.argv[1], sys.argv[2]
alerts = [json.loads(l) for l in open(path) if l.strip()]
by_user = {}
for a in alerts:
    by_user.setdefault(a["user"], []).append(a)

def peak(u):
    return max(by_user.get(u, []), key=lambda a: a["score"], default=None)

def rank(level):
    return {"none": 0, "info": 1, "alert": 2, "high": 3}.get(level, 0)

def peak_level(u):
    return max((rank(a["level"]) for a in by_user.get(u, [])), default=0)

def classes(u):
    return {a["class"] for a in by_user.get(u, [])}

def events(u):
    return [a["event"] for a in by_user.get(u, [])]

def clue_ids(u):
    return {r["clue"] for a in by_user.get(u, []) for r in a["reasons"]}

checks = []
def expect(name, ok, detail):
    checks.append((name, bool(ok), detail))

if pas == "A":
    p = peak("alice")
    expect("alice: remote agent shape reaches info without auditd",
           p and p["score"] >= 40 and "declared_agent" not in classes("alice") and {"rhythm.burst", "pty.none"} <= clue_ids("alice"),
           p and f'score {p["score"]} {p["level"]} clues {sorted(clue_ids("alice"))}')
    expect("bob: human session raises nothing", "bob" not in by_user, events("bob"))
    expect("carol: SetEnv declaration labelled through the sshrc hook",
           "declared_agent" in classes("carol") and any(a.get("agent") == "whotyped-simulate" for a in by_user.get("carol", [])),
           f'classes {sorted(classes("carol"))} events {events("carol")}')
    p = peak("dave")
    expect("dave: paramiko exec channels reach info at VERBOSE", p and p["score"] >= 40 and p["connections"] == 1,
           p and f'score {p["score"]} connections {p["connections"]}')
    p = peak("erin")
    expect("erin: local agent with skip flag is an alert", p and p["level"] in ("alert", "high") and p["mode"] == "local_agent" and p.get("agent") == "?claude-code",
           p and f'score {p["score"]} {p["level"]} {p["mode"]} {p.get("agent")}')
    p = peak("frank")
    expect("frank: ssh -tt keeps pty.none, spoofed AI_AGENT ignored",
           p and "pty.none" in clue_ids("frank") and "declared_agent" not in classes("frank") and p["mode"] == "remote_agent",
           p and f'score {p["score"]} mode {p["mode"]} classes {sorted(classes("frank"))}')
    stdin = open("/var/lib/whotyped/stdin-check.txt").read().strip()
    expect("sshrc hook leaves stdin to the command", stdin == "payload-through-stdin", repr(stdin))
    expect("grace: the stdin check itself was labelled as a declared agent", "declared_agent" in classes("grace"), sorted(classes("grace")))
    expect("forged declaration for a missing session is ignored",
           not any(a.get("agent") == "forged" for a in alerts), [a["user"] for a in alerts if a.get("agent") == "forged"])
else:
    p = peak("dave")
    expect("dave: DEBUG1 banner clue fires", "banner.library" in clue_ids("dave"), sorted(clue_ids("dave")))
    expect("dave: freeze violation raised", "freeze_violation" in events("dave"), events("dave"))
    expect("dave: later escalation to alert is reported inside the freeze",
           any(a["event"] in ("agent_detected", "agent_high") and rank(a["level"]) >= 2 for a in by_user.get("dave", [])),
           [(a["event"], a["level"], a["score"]) for a in by_user.get("dave", [])])
    expect("carol: declared agent in a freeze is a freeze violation",
           any(a["event"] == "freeze_violation" and a["class"] == "declared_agent" for a in by_user.get("carol", [])),
           [(a["event"], a["class"]) for a in by_user.get("carol", [])])
    expect("bob: human in a freeze stays quiet", "bob" not in by_user, events("bob"))

failed = 0
for name, ok, detail in checks:
    print(f'{"PASS" if ok else "FAIL"}  {name}  [{detail}]')
    failed += not ok
print(f"\n{len(checks) - failed}/{len(checks)} expectations met")
sys.exit(1 if failed else 0)
PY
