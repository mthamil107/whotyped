# Security policy

whotyped runs as root and reads authentication logs, so we take reports seriously and answer quickly.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on [github.com/mthamil107/whotyped](https://github.com/mthamil107/whotyped): open the **Security** tab and choose **Report a vulnerability**. That creates a private advisory that only maintainers can see. Do not open a public issue and do not post details in discussions or chat.

Please include: the version (`whotyped version`), distro and OpenSSH version, what you did, what happened, and what you expected. A proof of concept helps; a fix is welcome but not required.

## What counts

In scope:

- Privilege escalation, file overwrite or code execution via crafted log lines, audit records, `/proc` contents, environment variables (including `AI_AGENT` values), config files or rule packs
- Log-line injection that makes whotyped emit false records or suppress real ones
- Alert or state file writes outside `/var/lib/whotyped`
- Leaks of command text or other data beyond what the `privacy.*` settings allow
- Sink issues: credential exposure, SSRF via webhook URLs, TLS verification bypass
- Supply chain: release signing, checksums, build reproducibility
- Anything in the Ansible role, Helm chart or lab scripts that would weaken the host they run on

Out of scope (still useful as normal issues):

- Detection evasion. whotyped documents that agents can evade it; a new evasion is a detection issue, not a vulnerability, unless it also crashes or corrupts the daemon
- False positives and false negatives
- Denial of service that requires root on the same host
- Findings in third-party SIEMs consuming our rules

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| Triage and severity (CVSS 3.1) | 7 days |
| Fix for high and critical | 30 days |
| Fix for medium and low | 90 days |
| Coordinated public disclosure | 90 days after report, earlier if a fix ships sooner, later only by agreement with the reporter |

We publish a GitHub security advisory and a CVE (via GitHub's CNA) for anything medium or above, credit the reporter unless they prefer not to be named, and note the fix in the release notes.

## Supported versions

| Version | Supported |
|---|---|
| `main` (pre-release, no tagged version yet) | yes |
| anything else | no |

Once releases start, the latest minor (0.x) is supported, and the previous minor gets security fixes for 90 days after the next minor ships.

Before 1.0, minor releases may change configuration and alert schema fields; the alert `schema` field (`whotyped.alert.v1`) is versioned so that consumers can tell.

## Hardening notes for operators

- Run the shipped systemd unit; it uses `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp` and read-only paths.
- Keep `/etc/whotyped/config.yaml` at `0640 root:root`; it may contain webhook URLs or SMTP credentials.
- Webhook URLs should point at hosts you control or the vendor's documented endpoint. The daemon does not follow redirects to other hosts.
- Verify release signatures (cosign keyless bundle over the checksums file; instructions in the release notes).
- If you enable `privacy.command_text: full`, treat `alerts.jsonl` as sensitive as the audit log itself.
