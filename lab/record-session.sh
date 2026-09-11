#!/usr/bin/env bash
# record-session.sh: capture one labelled recording on the lab host.
#
# Usage (as root, on the lab host):
#   ./record-session.sh <label> [duration_seconds]        # wait, then export
#   ./record-session.sh <label> -- <command...>            # run a local command, then export
#
# Output: lab/recordings/<label>-<UTC ts>/ with meta.json, journal.jsonl, audit.log,
# auth.log (if present), proc/<epoch>/<pid>.json snapshots, alerts.jsonl (if whotyped runs).
# Ctrl-C ends the wait early and still exports.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "run as root (journal, audit.log and /proc/*/environ need it)" >&2; exit 2; fi
if [ $# -lt 1 ]; then sed -n '2,10p' "$0"; exit 2; fi

LABEL="$1"; shift
DURATION=600
CMD=()
if [ $# -gt 0 ]; then
  if [ "$1" = "--" ]; then shift; CMD=("$@"); else DURATION="$1"; fi
fi

case "$LABEL" in
  human-*|automation-*|agent-*|declared-*|mixed-*) ;;
  *) echo "label should start with human-|automation-|agent-|declared-|mixed- (got '$LABEL')" >&2 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$HERE/recordings/$LABEL-$TS"
mkdir -p "$OUT/proc"
START_EPOCH="$(date +%s)"

# Environment variables worth keeping from /proc/PID/environ. Everything else is dropped.
ENV_KEEP='AI_AGENT AI_AGENT_SESSION AI_AGENT_OPERATOR AGENT AGENT_SESSION_ID CLAUDECODE CLAUDE_CODE CLAUDE_CODE_ENTRYPOINT CODEX_SANDBOX CODEX_THREAD_ID CODEX_CI GEMINI_CLI CURSOR_AGENT CURSOR_TRACE_ID GOOSE_PROVIDER GOOSE_TERMINAL OPENCODE OPENCODE_CLIENT COPILOT_MODEL COPILOT_ALLOW_ALL Q_TERM QTERM_SESSION_ID TERM_PROGRAM SSH_CONNECTION SSH_TTY SSH_ORIGINAL_COMMAND TERM'

snapshot_loop() {
  # One JSON file per process with a real login session, every 2 seconds.
  while true; do
    EP="$(date +%s)"
    D="$OUT/proc/$EP"; mkdir -p "$D"
    ENV_KEEP="$ENV_KEEP" OUTDIR="$D" python3 - <<'PY' 2>/dev/null || true
import os, json, sys
keep = set(os.environ["ENV_KEEP"].split())
out = os.environ["OUTDIR"]
UNSET = 4294967295
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    p = f"/proc/{pid}"
    try:
        ses = int(open(f"{p}/sessionid").read().strip())
        auid = int(open(f"{p}/loginuid").read().strip())
        if ses == UNSET or auid < 1000:
            continue
        status = {}
        for line in open(f"{p}/status"):
            k, _, v = line.partition(":")
            status[k] = v.strip()
        cmdline = open(f"{p}/cmdline", "rb").read().split(b"\0")
        cmdline = [c.decode("utf-8", "replace") for c in cmdline if c]
        env = {}
        try:
            for kv in open(f"{p}/environ", "rb").read().split(b"\0"):
                k, _, v = kv.partition(b"=")
                k = k.decode("utf-8", "replace")
                if k in keep:
                    env[k] = v.decode("utf-8", "replace")[:256]
        except OSError:
            pass
        try:
            exe = os.readlink(f"{p}/exe")
        except OSError:
            exe = ""
        stat = open(f"{p}/stat").read()
        starttime = int(stat.rsplit(")", 1)[1].split()[19])
        rec = {
            "pid": int(pid), "ppid": int(status.get("PPid", "0")),
            "uid": int(status.get("Uid", "0").split()[0]), "loginuid": auid, "ses": ses,
            "comm": status.get("Name", ""), "exe": exe, "cmdline": cmdline, "env": env,
            "starttime": starttime,
        }
        with open(os.path.join(out, f"{pid}.json"), "w") as f:
            json.dump(rec, f)
    except (OSError, ValueError, IndexError):
        continue
PY
    sleep 2
  done
}

snapshot_loop &
SNAP_PID=$!

finish() {
  set +e
  kill "$SNAP_PID" 2>/dev/null; wait "$SNAP_PID" 2>/dev/null
  END_EPOCH="$(date +%s)"
  echo "exporting logs for $START_EPOCH..$END_EPOCH"
  if command -v journalctl >/dev/null; then
    journalctl -o json --since "@$START_EPOCH" --until "@$((END_EPOCH+1))" \
      SYSLOG_IDENTIFIER=sshd + SYSLOG_IDENTIFIER=sshd-session + SYSLOG_IDENTIFIER=sshd-auth + SYSLOG_IDENTIFIER=ai_agent \
      > "$OUT/journal.jsonl" 2>/dev/null || true
  fi
  for f in /var/log/auth.log /var/log/secure; do
    [ -r "$f" ] && awk -v s="$START_EPOCH" 'BEGIN{} {print}' "$f" | tail -n 5000 > "$OUT/$(basename "$f")" || true
  done
  if command -v ausearch >/dev/null; then
    ausearch --raw -ts "$(date -d "@$START_EPOCH" '+%m/%d/%Y %H:%M:%S')" -te "$(date -d "@$END_EPOCH" '+%m/%d/%Y %H:%M:%S')" \
      > "$OUT/audit.log" 2>/dev/null || true
  elif [ -r /var/log/audit/audit.log ]; then
    tail -n 20000 /var/log/audit/audit.log > "$OUT/audit.log" || true
  fi
  [ -r /var/lib/whotyped/alerts.jsonl ] && cp /var/lib/whotyped/alerts.jsonl "$OUT/alerts.jsonl" || true
  OPENSSH="$(ssh -V 2>&1 | awk '{print $1}')"
  LOGLEVEL="$( (sshd -T 2>/dev/null || true) | awk '$1=="loglevel"{print $2}')"
  AUDITD="false"; auditctl -l 2>/dev/null | grep -q whotyped && AUDITD="true"
  DISTRO="$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}-${VERSION_ID:-}")"
  cat > "$OUT/meta.json" <<JSON
{"label":"$LABEL","host":"$(hostname)","start":"$(date -u -d "@$START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)","end":"$(date -u -d "@$END_EPOCH" +%Y-%m-%dT%H:%M:%SZ)","recorded_by":"${SUDO_USER:-root}","command":"${CMD[*]:-}","host_profile":{"distro":"$DISTRO","openssh":"$OPENSSH","auditd":$AUDITD,"loglevel":"${LOGLEVEL:-unknown}"},"notes":""}
JSON
  echo "recording: $OUT"
  echo "  journal lines: $(wc -l < "$OUT/journal.jsonl" 2>/dev/null || echo 0)"
  echo "  audit lines:   $(wc -l < "$OUT/audit.log" 2>/dev/null || echo 0)"
  echo "  proc snapshots: $(ls "$OUT/proc" | wc -l)"
  echo "next: python3 $HERE/label.py $OUT --scrub"
}
trap finish EXIT INT TERM

echo "recording '$LABEL' -> $OUT"
if [ ${#CMD[@]} -gt 0 ]; then
  echo "running: ${CMD[*]}"
  "${CMD[@]}" || true
else
  echo "waiting $DURATION s (Ctrl-C to stop early); run the scenario now"
  sleep "$DURATION"
fi
