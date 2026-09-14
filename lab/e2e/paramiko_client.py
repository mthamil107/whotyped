#!/usr/bin/env python3
"""Drive an SSH server the way a paramiko-based MCP SSH server does: one
transport, one exec channel per tool call, no PTY, a short think time between
calls. Usage: paramiko_client.py USER HOST KEYFILE [N]"""
import random
import sys
import time

import paramiko

user, host, keyfile = sys.argv[1], sys.argv[2], sys.argv[3]
n = int(sys.argv[4]) if len(sys.argv) > 4 else 10
cmds = [
    "uname -a",
    "cat /etc/os-release | head -n 3",
    "df -h / 2>&1 | tail -n 1",
    "ls -la /var/log 2>&1 | head -n 20",
    "ps aux --sort=-%mem | head -n 5",
    "cd /tmp && ls -la 2>&1 | head -n 10",
    "free -m",
    "id",
    "uptime",
    "sed -n '1,5p' /etc/passwd",
]
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, key_filename=keyfile, look_for_keys=False, allow_agent=False)
for i in range(n):
    _, out, _ = client.exec_command(cmds[i % len(cmds)])
    out.read()
    time.sleep(random.uniform(0.4, 1.2))
client.close()
print(f"paramiko: ran {n} exec channels as {user}@{host}")
