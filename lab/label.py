#!/usr/bin/env python3
"""label.py: turn a lab recording directory into events.jsonl + expected.json.

Usage: python3 lab/label.py <recording-dir> [--scrub] [--user NAME]

Input (from record-session.sh):
  meta.json        label, host, start, end, host_profile
  journal.jsonl    journalctl -o json for sshd, sshd-session, sshd-auth
  audit.log        raw auditd records (ausearch --raw or a tail of audit.log)
  proc/<epoch>/<pid>.json   process snapshots

Output, written into the same directory:
  events.jsonl     one internal/event.Event per line, sorted by ts
  expected.json    expected class and score band derived from the label prefix

--scrub replaces usernames, IPs and key fingerprints with stable placeholders
(alice -> user1, 203.0.113.5 -> 10.0.0.1, SHA256:... -> SHA256:FP1) so the files
can be committed. Standard library only.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

SSHD_IDS = {"sshd", "sshd-session", "sshd-auth"}
UNSET = 4294967295
EXECVE_SYSCALLS = {"59", "322", "221", "281"}  # x86_64 execve/execveat, aarch64 execve/execveat

RE_ACCEPTED = re.compile(r"^Accepted (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2(?:: (\S+) (\S+))?")
RE_FAILED = re.compile(r"^(?:Failed \S+ for|Invalid user|Connection closed by (?:authenticating|invalid) user) (?:invalid user )?(\S+)(?: from)? (\S+) port (\d+)")
RE_SESSION = re.compile(r"^Starting session: (shell|command|subsystem '[^']+'|forced-command \([^)]*\) '[^']*')(?: on (pts/\d+))? for (\S+) from (\S+) port (\d+) id (\d+)")
RE_DISC = re.compile(r"^(?:Disconnected from user (\S+) (\S+) port (\d+)|Received disconnect from (\S+) port (\d+))")
RE_BANNER = re.compile(r"^(?:Remote protocol version [\d.]+, remote software version|Client protocol version [\d.]+; client software version) (.+)$")
RE_PAM = re.compile(r"pam_unix\(sshd:session\): session opened for user (\S+?)(?:\(uid=(\d+)\))? by")
RE_AUDIT_HEAD = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s*(.*)$")
RE_KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def strip_suffix(msg: str) -> str:
    for s in (" [preauth]", " [postauth]"):
        if msg.endswith(s):
            msg = msg[: -len(s)]
    return msg


def parse_journal(path):
    events = []
    if not os.path.exists(path):
        return events
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if j.get("SYSLOG_IDENTIFIER") not in SSHD_IDS:
                continue
            msg = j.get("MESSAGE", "")
            if isinstance(msg, list):  # journald emits byte arrays for non-UTF8
                msg = bytes(msg).decode("utf-8", "replace")
            msg = strip_suffix(msg)
            try:
                ts = int(j.get("__REALTIME_TIMESTAMP", "0")) / 1_000_000
            except ValueError:
                continue
            pid = int(j.get("SYSLOG_PID") or j.get("_PID") or 0)
            ev = {"ts": iso(ts), "source": "sshlog", "pid": pid, "fields": {}}
            m = RE_ACCEPTED.match(msg)
            if m:
                method, user, ip, port, keytype, fp = m.groups()
                ev.update(kind="ssh.auth_ok", user=user, src_ip=ip, src_port=int(port))
                ev["fields"]["method"] = method
                if keytype:
                    ev["fields"]["keytype"] = keytype
                    ev["fields"]["fp"] = fp
                events.append(ev)
                continue
            m = RE_SESSION.match(msg)
            if m:
                stype, tty, user, ip, port, chan = m.groups()
                ev.update(kind="ssh.session_start", user=user, src_ip=ip, src_port=int(port))
                ev["fields"].update(stype=stype.split(" ")[0] if stype.startswith("forced") else stype, tty=tty or "", chan=chan)
                events.append(ev)
                continue
            m = RE_FAILED.match(msg)
            if m:
                user, ip, port = m.groups()
                ev.update(kind="ssh.auth_fail", user=user, src_ip=ip, src_port=int(port))
                events.append(ev)
                continue
            m = RE_DISC.match(msg)
            if m:
                user, ip, port, ip2, port2 = m.groups()
                ev.update(kind="ssh.disconnect", src_ip=ip or ip2, src_port=int(port or port2))
                if user:
                    ev["user"] = user
                events.append(ev)
                continue
            m = RE_BANNER.match(msg)
            if m:
                ev.update(kind="ssh.banner")
                ev["fields"]["banner"] = m.group(1).strip()
                events.append(ev)
                continue
            m = RE_PAM.search(msg)
            if m:
                ev.update(kind="ssh.pam_open", user=m.group(1))
                if m.group(2):
                    ev["fields"]["uid"] = m.group(2)
                events.append(ev)
                continue
    return events


# Keys whose values auditd prints as a quoted string, or as uppercase hex when the string
# contains a quote, a space, a control byte or a non-ASCII byte. Numeric keys (pid, ses,
# auid, syscall, ...) are never hex-encoded, so decoding them would corrupt e.g. pid=3102.
RE_STRING_KEY = re.compile(r"^(a\d+(\[\d+\])?|proctitle|cwd|name|comm|exe|key|acct|hostname|terminal|addr|msg|op|grantors)$")


def unquote(v: str, key: str = "") -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    if RE_STRING_KEY.match(key) and re.fullmatch(r"[0-9A-F]+", v) and len(v) % 2 == 0 and len(v) >= 2:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def parse_audit(path):
    events = []
    if not os.path.exists(path):
        return events
    groups = {}
    order = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.split("\x1d", 1)[0].strip()  # drop ENRICHED suffix
            m = RE_AUDIT_HEAD.match(line)
            if not m:
                continue
            rtype, secs, msecs, serial, rest = m.groups()
            key = (secs, msecs, serial)
            if key not in groups:
                groups[key] = {}
                order.append(key)
            kv = {k: unquote(v, k) for k, v in RE_KV.findall(rest)}
            groups[key].setdefault(rtype, []).append(kv)
    for key in order:
        secs, msecs, _ = key
        ts = iso(int(secs) + int(msecs) / 1000)
        recs = groups[key]
        if "SYSCALL" in recs:
            sc = recs["SYSCALL"][0]
            if sc.get("syscall") not in EXECVE_SYSCALLS and sc.get("key") != "whotyped":
                continue
            argv = []
            if "EXECVE" in recs:
                ex = recs["EXECVE"][0]
                try:
                    argc = int(ex.get("argc", "0"))
                except ValueError:
                    argc = 0
                for i in range(argc):
                    a = ex.get(f"a{i}")
                    if a is None:  # long args split as a{i}[0], a{i}[1] ...
                        parts = [ex[k] for k in sorted(ex) if k.startswith(f"a{i}[")]
                        a = "".join(parts)
                    argv.append(a)
            ses = int(sc.get("ses", "0") or 0)
            ev = {
                "ts": ts, "kind": "audit.execve", "source": "auditd",
                "pid": int(sc.get("pid", "0") or 0), "ses": -1 if ses == UNSET else ses,
                "fields": {
                    "argv0": argv[0] if argv else sc.get("comm", ""),
                    "cmd": " ".join(argv),
                    "exe": sc.get("exe", ""), "comm": sc.get("comm", ""),
                    "cwd": recs.get("CWD", [{}])[0].get("cwd", ""),
                    "tty": sc.get("tty", ""), "uid": sc.get("uid", ""), "auid": sc.get("auid", ""),
                    "ppid": sc.get("ppid", ""),
                },
            }
            events.append(ev)
        elif "USER_START" in recs or "USER_LOGIN" in recs:
            r = (recs.get("USER_LOGIN") or recs.get("USER_START"))[0]
            inner = {k: unquote(v, k) for k, v in RE_KV.findall(r.get("msg", ""))}
            ses = int(r.get("ses", "0") or 0)
            events.append({
                "ts": ts, "kind": "audit.login", "source": "auditd",
                "pid": int(r.get("pid", "0") or 0), "ses": -1 if ses == UNSET else ses,
                "user": inner.get("acct", ""), "src_ip": inner.get("addr", ""),
                "fields": {"acct": inner.get("acct", ""), "addr": inner.get("addr", ""),
                           "terminal": inner.get("terminal", ""), "res": inner.get("res", "")},
            })
        elif "USER_END" in recs or "USER_LOGOUT" in recs:
            r = (recs.get("USER_END") or recs.get("USER_LOGOUT"))[0]
            inner = {k: unquote(v, k) for k, v in RE_KV.findall(r.get("msg", ""))}
            ses = int(r.get("ses", "0") or 0)
            events.append({
                "ts": ts, "kind": "audit.logout", "source": "auditd",
                "pid": int(r.get("pid", "0") or 0), "ses": -1 if ses == UNSET else ses,
                "user": inner.get("acct", ""), "fields": {},
            })
    return events


def parse_proc(root):
    events = []
    if not os.path.isdir(root):
        return events
    seen = set()
    for epoch in sorted(os.listdir(root), key=lambda s: int(s) if s.isdigit() else 0):
        d = os.path.join(root, epoch)
        if not os.path.isdir(d) or not epoch.isdigit():
            continue
        for fn in os.listdir(d):
            try:
                with open(os.path.join(d, fn), encoding="utf-8") as f:
                    p = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            ident = (p.get("pid"), p.get("starttime"))
            if ident in seen:
                continue
            seen.add(ident)
            cmdline = p.get("cmdline") or []
            fields = {
                "comm": p.get("comm", ""), "exe": p.get("exe", ""),
                "argv0": cmdline[0] if cmdline else "", "cmd": " ".join(cmdline),
                "uid": str(p.get("uid", "")), "loginuid": str(p.get("loginuid", "")),
                "ppid": str(p.get("ppid", "")),
            }
            for k, v in (p.get("env") or {}).items():
                fields[f"env.{k}"] = v
            events.append({
                "ts": iso(int(epoch)), "kind": "proc.seen", "source": "procfs",
                "pid": int(p.get("pid", 0)), "ses": int(p.get("ses", 0)), "fields": fields,
            })
    return events


def scrub(events):
    users, ips, fps = {}, {}, {}

    def u(x):
        if not x or x in ("root",):
            return x
        return users.setdefault(x, f"user{len(users) + 1}")

    def ip(x):
        if not x:
            return x
        return ips.setdefault(x, f"10.0.0.{len(ips) + 1}")

    def fp(x):
        return fps.setdefault(x, f"SHA256:FP{len(fps) + 1}")

    for e in events:
        if "user" in e:
            e["user"] = u(e["user"])
        if "src_ip" in e:
            e["src_ip"] = ip(e["src_ip"])
        f = e.get("fields", {})
        for k in ("acct",):
            if k in f:
                f[k] = u(f[k])
        for k in ("addr",):
            if k in f:
                f[k] = ip(f[k])
        if "fp" in f:
            f["fp"] = fp(f["fp"])
        for k in ("cwd", "cmd", "argv0", "exe"):
            if k in f:
                for real, fake in users.items():
                    f[k] = f[k].replace(f"/home/{real}", f"/home/{fake}")
        if "env.AI_AGENT_OPERATOR" in f:
            f["env.AI_AGENT_OPERATOR"] = u(f["env.AI_AGENT_OPERATOR"])
        if "env.SSH_CONNECTION" in f:  # "clientIP clientPort serverIP serverPort"
            parts = f["env.SSH_CONNECTION"].split()
            f["env.SSH_CONNECTION"] = " ".join(ip(p) if i in (0, 2) else p for i, p in enumerate(parts))
    return users


def expected_for(label, user, meta):
    prefix = label.split("-", 1)[0]
    table = {
        "human": ("human", 0, 39),
        "automation": ("human", 0, 39),
        "agent": ("suspected_agent", 70, 100),
        "declared": ("declared_agent", 0, 100),
        "mixed": ("suspected_agent", 70, 100),
    }
    cls, lo, hi = table.get(prefix, ("suspected_agent", 70, 100))
    return {
        "label": label,
        "class": cls,
        "min_score": lo,
        "max_score": hi,
        "user": user,
        "mode": "remote_agent" if "local" not in label else "local_agent",
        "must_have_clues": [],
        "notes": meta.get("notes", "") + (" (mixed: set expectations by hand)" if prefix == "mixed" else ""),
        "recorded": meta.get("start", ""),
        "host_profile": meta.get("host_profile", {}),
    }


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    d = argv[1]
    do_scrub = "--scrub" in argv
    forced_user = None
    if "--user" in argv:
        forced_user = argv[argv.index("--user") + 1]
    meta = {}
    mp = os.path.join(d, "meta.json")
    if os.path.exists(mp):
        with open(mp, encoding="utf-8") as f:
            meta = json.load(f)
    label = meta.get("label") or os.path.basename(os.path.normpath(d)).rsplit("-", 1)[0]

    events = parse_journal(os.path.join(d, "journal.jsonl"))
    events += parse_audit(os.path.join(d, "audit.log"))
    events += parse_proc(os.path.join(d, "proc"))
    events.sort(key=lambda e: e["ts"])

    # Main user: most frequent user on auth_ok events.
    counts = {}
    for e in events:
        if e.get("kind") == "ssh.auth_ok" and e.get("user"):
            counts[e["user"]] = counts.get(e["user"], 0) + 1
    user = forced_user or (max(counts, key=counts.get) if counts else "")

    if do_scrub:
        mapping = scrub(events)
        user = mapping.get(user, user)

    with open(os.path.join(d, "events.jsonl"), "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n")
    exp_path = os.path.join(d, "expected.json")
    if not os.path.exists(exp_path):
        with open(exp_path, "w", encoding="utf-8") as f:
            json.dump(expected_for(label, user, meta), f, indent=2)
            f.write("\n")
    kinds = {}
    for e in events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"{label}: {len(events)} events -> {os.path.join(d, 'events.jsonl')}")
    for k in sorted(kinds):
        print(f"  {k:20s} {kinds[k]}")
    if not events:
        print("  warning: no events parsed; check journal.jsonl / audit.log / proc/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
