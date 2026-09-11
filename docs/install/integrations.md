# Integrations

whotyped writes alerts to `/var/lib/whotyped/alerts.jsonl` and, when configured, to syslog, an HTTP webhook, email and a Prometheus endpoint. Everything below builds on those. Exact configuration keys are in `deploy/config.example.yaml`; treat the snippets here as illustrations and that file as authoritative.

| Target | What you deploy | Where |
|---|---|---|
| Wazuh | decoder + rules 100500–100510, `<localfile>` on the JSON file | `deploy/wazuh/` |
| Sigma (Splunk, Elastic, Sentinel, …) | 4 rules converted with sigma-cli | `deploy/sigma/` |
| Falco | rules file for agent processes on the host | `deploy/falco/` |
| Prometheus | scrape the `sinks.prometheus` listener | config |
| Slack / Teams | webhook sink | config |
| Email | SMTP sink | config |
| Ansible | role that installs and configures everything | `deploy/ansible/` |
| Kubernetes | DaemonSet chart | `deploy/helm/` |

## Wazuh

Two ways to get alerts in:

1. Read the file directly on each host with the Wazuh agent (recommended):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/whotyped/alerts.jsonl</location>
  <label key="source">whotyped</label>
</localfile>
```

The built-in JSON decoder flattens the alert fields (`event`, `level`, `user`, `score`, …). Copy `deploy/wazuh/local_rules.xml` to `/var/ossec/etc/rules/` on the manager and restart it.

2. Send via syslog (`sinks.syslog` with tag `whotyped`) and use `deploy/wazuh/local_decoder.xml`, which unwraps the syslog line and hands the JSON to the JSON decoder.

Rule levels: declared agent 5, suspected (info) 5, alert 10, high 12, freeze violation 13, still active 7, ended 3, plus a composite for repeated alerts on the same user within an hour. See `deploy/wazuh/README.md`.

## Sigma

Four rules in `deploy/sigma/`:

- `lnx_auditd_ai_agent_skip_permissions.yml`: `claude --dangerously-skip-permissions`, `gemini --yolo`, `codex --full-auto`, `q chat --trust-all-tools`, `copilot --allow-all-tools` and friends, from auditd EXECVE records. Works without whotyped at all.
- `lnx_auditd_ai_agent_binary_in_ssh_session.yml`: agent binaries executed with `tty=(none)`.
- `lnx_sshd_uncommon_client_banner.yml`: SSH client banner that is not OpenSSH/PuTTY/WinSCP/Termius/MobaXterm. Needs `LogLevel DEBUG1`.
- `lnx_whotyped_agent_suspected.yml`: whotyped's own `agent_detected` at level `alert` or `high`, for when alerts are shipped as syslog lines.

Convert with sigma-cli, for example `sigma convert -t splunk -p splunk_sysmon_acceleration deploy/sigma/` or `-t lucene` for Elastic. Details and validation in `deploy/sigma/README.md`.

## Falco

`deploy/falco/whotyped_rules.yaml` raises Falco events when a known agent binary runs under sshd, when a process carries an agent environment variable, or when a skip flag is passed. It is independent of whotyped's daemon and marked UNTESTED until we have run it on a Falco 0.38+ node; treat it as a starting point. Load with `-r` or drop into `/etc/falco/rules.d/`.

## Prometheus

Enable `sinks.prometheus` (`enabled: false` by default, `listen: 127.0.0.1:9477`); it serves `/metrics` in text exposition format. Metrics, all prefixed `whotyped_`, with no usernames or IPs as labels:

```
whotyped_sessions_total{class}
whotyped_active_sessions{class}
whotyped_alerts_total{level,sink}
whotyped_events_total{kind}
whotyped_events_dropped_total
whotyped_reader_up{name}
whotyped_build_info{version}
```

Useful alert rules: `whotyped_reader_up == 0` for 5 minutes (a reader died: auditd stopped, journald cursor lost); `increase(whotyped_alerts_total{level="high"}[1h]) > 0`; `whotyped_events_dropped_total` increasing (host too busy or channel too small).

## Slack and Microsoft Teams

Both use the webhook sink with `format: slack` or `format: teams` (`json` posts the raw alert, `discord` is also available). Slack incoming webhooks accept `{"text": "..."}`; Teams incoming webhooks (Workflows-based since 2024) accept an Adaptive Card payload. The sink posts a compact message: host, user, source IP, score, level, top three reasons and the `actions_hint`. Configure per-level routing so that `info` stays in the file and only `alert` and `high` reach chat, or you will train people to ignore it.

Set a request timeout and expect retries (the dispatcher retries transient failures with backoff and never blocks detection on a slow sink).

## Email

SMTP sink with STARTTLS or implicit TLS, one message per alert at level `alert` or above, plus optionally the weekly `whotyped report --format md` output from a cron job:

```
0 8 * * 1 root /usr/local/bin/whotyped report --since 7d --format md | mail -s "whotyped weekly" secops@example.com
```

## Generic log shippers

Vector, Fluent Bit, Filebeat and Promtail all read `alerts.jsonl` as newline-delimited JSON. Use the `schema` field (`whotyped.alert.v1`) to route, `level` to filter, and keep `reasons` as a nested array; do not flatten it into a string or you lose the per-clue weights.

## Splunk and Elastic without Sigma

Splunk: `sourcetype=_json` on the file, or `sourcetype=whotyped:alert` with `KV_MODE=json`. Search `index=linux sourcetype=whotyped:alert level=alert OR level=high | table _time host user src_ip score agent reasons{}.clue`.

Elastic: Filebeat `json.keys_under_root: true`, an index template with `reasons` as `nested`. The Sigma rules convert to KQL/Lucene with sigma-cli if you want them as detection rules rather than searches.
