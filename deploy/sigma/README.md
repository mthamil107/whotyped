# Sigma rules

Four rules, Sigma v2 format, status `experimental`.

| File | Source | Needs | Level |
|---|---|---|---|
| `lnx_auditd_ai_agent_skip_permissions.yml` | auditd EXECVE | auditd execve rule | high |
| `lnx_auditd_ai_agent_binary_in_ssh_session.yml` | auditd SYSCALL | auditd execve rule | medium |
| `lnx_sshd_uncommon_client_banner.yml` | sshd log | `LogLevel DEBUG1` | low |
| `lnx_whotyped_agent_suspected.yml` | whotyped alerts via syslog | whotyped syslog sink | high |

The first three work without whotyped installed. The fourth is for shops that ship `alerts.jsonl` as syslog text rather than as structured JSON; if your pipeline parses the JSON, write the equivalent query on the `event` and `level` fields instead.

## Validate

```sh
pipx install sigma-cli
sigma check deploy/sigma/
```

`sigma check` validates syntax and the built-in validators (UUID, date format, tag namespace, unused selections). Run it in CI; the repository's own CI does. Auditd field names (`type`, `a0`, `comm`, `tty`, `auid`) follow the conventions used in the SigmaHQ `linux/auditd` rules so that the standard pipelines map them.

## Convert

Install the backend for your SIEM, then convert. Examples:

```sh
# Splunk
pipx inject sigma-cli pysigma-backend-splunk
sigma convert -t splunk deploy/sigma/lnx_auditd_ai_agent_skip_permissions.yml

# Elastic (Lucene / KQL / ES|QL)
pipx inject sigma-cli pysigma-backend-elasticsearch
sigma convert -t lucene deploy/sigma/
sigma convert -t esql deploy/sigma/

# Microsoft Sentinel (KQL)
pipx inject sigma-cli pysigma-backend-microsoft365defender   # or pysigma-backend-kusto, depending on version
sigma convert -t kusto -p sentinel_asim deploy/sigma/lnx_whotyped_agent_suspected.yml

# Loki / Grafana
pipx inject sigma-cli pysigma-backend-loki
sigma convert -t loki deploy/sigma/
```

Backend and pipeline names change between pySigma releases; `sigma list targets` and `sigma list pipelines` print what your install supports. There is no Wazuh backend; use the native XML in `deploy/wazuh/` instead.

## Field mapping notes

- Auditd: raw `audit.log` needs a parser that splits records into fields. Auditbeat, the Splunk Linux Auditd add-on, Wazuh and rsyslog `mmaudit` all do; the field names differ slightly (Auditbeat puts `a0` under `auditd.data.a0`). Use a pipeline (`-p`) for your ingest tool rather than editing the rules.
- With `log_format = ENRICHED` (RHEL default) the `AUID="alice"` text is appended after a `0x1D` separator; the numeric `auid=` is still present and is what the rules match.
- sshd: the banner rule matches on message text only. It needs no field mapping but it does need DEBUG1 (see `docs/install/sshd-and-auditd.md`).
- OpenSSH 9.8+ logs from `sshd-session` (and `sshd-auth` since 10.0), not `sshd`. If your `service: sshd` pipeline filters on the program name, add both.

## Contributing rules upstream

After a month of field use with a documented false-positive rate, the auditd rules are candidates for SigmaHQ. Keep the `status: experimental` and the `whotyped project` author until then.
