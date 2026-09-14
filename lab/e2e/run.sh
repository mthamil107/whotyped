#!/bin/sh
# Build the Linux binary and the lab image, run both passes, and save the
# output under lab/recordings/e2e-<timestamp>/ (gitignored). Needs Docker and
# Go. Exit status is non-zero when any pass has a failed expectation.
set -eu
cd "$(dirname "$0")/../.."
OUT="lab/recordings/e2e-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/whotyped-linux-amd64 ./cmd/whotyped
docker build -q -f lab/e2e/Dockerfile -t whotyped-e2e:local . >/dev/null

status=0
run_pass() { # $1 pass, $2 sshd log level, $3 extra docker args
  name="whotyped-e2e-$1"
  docker rm -f "$name" >/dev/null 2>&1 || true
  # SYS_PTRACE lets root read other users' /proc/PID/environ; the AUDIT caps
  # let pam_loginuid set a login uid inside the container.
  docker run -d --name "$name" --cap-add SYS_PTRACE --cap-add AUDIT_CONTROL --cap-add AUDIT_WRITE \
    -e SSHD_LOGLEVEL="$2" $3 whotyped-e2e:local >/dev/null
  sleep 4
  rc=0
  docker exec "$name" /usr/local/bin/scenarios.sh "$1" > "$OUT/pass-$1.txt" 2>&1 || rc=$?
  cat "$OUT/pass-$1.txt"
  for f in alerts.jsonl daemon.log check.txt fix.txt; do
    docker cp "$name:/var/lib/whotyped/$f" "$OUT/pass-$1-$f" >/dev/null 2>&1 || true
  done
  docker cp "$name:/var/log/auth.log" "$OUT/pass-$1-auth.log" >/dev/null 2>&1 || true
  docker rm -f "$name" >/dev/null
  [ "$rc" -eq 0 ] || status=1
}

run_pass A VERBOSE ""
run_pass B DEBUG1 "-e WHOTYPED_LAB_FREEZE=1"
echo "saved to $OUT"
exit "$status"
