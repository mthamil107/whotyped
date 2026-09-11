# procfs fixtures

Each directory is a snapshot of `/proc` (plus `etc/passwd`) consumed by
`internal/readers/procfs` tests through `os.DirFS` / `fstest.MapFS`.

Because git on Windows cannot carry `/proc`-style symlinks, `PID/exe` and
`PID/fd/N` are regular files whose content is the link target
(`/usr/bin/bash`, `socket:[54321]`, `pipe:[54330]`). `readLink` falls back to
that convention only when the FS has no symlink to read.

| tree | scenario | expected procfs events |
|---|---|---|
| `local-agent` | alice (ses 7) runs `claude --dangerously-skip-permissions` (pid 4411) with `CLAUDECODE=1`; Bash-tool child `bash -c` (4420); a flags-only `bash -c 'gemini --yolo …'` (4430); ESTABLISHED to 160.79.104.10:443 owned by 4411 (inode 54321); SYN_SENT v4-mapped to 160.79.104.11:443 owned by nobody | proc.seen 4411/4420/4430, net.conn x2 |
| `human-admin` | alice (ses 3) interactive bash, vim, sudo on pts/1 | none |
| `mcp-remote` | bob (ses 12) only `bash -c` / `sh -c` exec children of sshd-session, no PTY, no agent env | none (sshlog carries this case) |

Regenerate with the script in the T3 notes; do not hand-edit `environ` or
`cmdline` (NUL-separated).
