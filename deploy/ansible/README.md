# Ansible role: whotyped

Installs whotyped on Debian/Ubuntu and RHEL-family hosts: package (deb/rpm from a URL) or a binary you ship, config from a template, sshd drop-in (`LogLevel VERBOSE`, `AcceptEnv AI_AGENT AI_AGENT_*`), auditd rules, and the systemd service.

Tested syntax with `ansible-lint` conventions; UNTESTED against live hosts as of 2026-09-11. Run with `--check --diff` first.

## Use

```yaml
# playbook.yml
- hosts: linux_servers
  become: true
  roles:
    - role: whotyped
      vars:
        whotyped_version: "0.1.0"
        whotyped_install_method: package     # package | binary
        whotyped_sshd_loglevel: VERBOSE      # VERBOSE | DEBUG1 (see docs/install/sshd-and-auditd.md)
        whotyped_manage_auditd: true
        whotyped_webhook_url: ""             # Slack/Teams incoming webhook, optional
```

```sh
ansible-playbook -i inventory playbook.yml --check --diff
ansible-playbook -i inventory playbook.yml
```

## Variables

See `roles/whotyped/defaults/main.yml`. The important ones:

| Variable | Default | Notes |
|---|---|---|
| `whotyped_version` | `0.1.0` | release tag without `v` |
| `whotyped_install_method` | `package` | `package` downloads deb/rpm from GitHub releases; `binary` copies `whotyped_binary_src` from the controller |
| `whotyped_release_base_url` | GitHub releases URL | override for an internal mirror |
| `whotyped_binary_src` | `files/whotyped` | path on the controller when `binary` |
| `whotyped_manage_sshd` | `true` | writes `/etc/ssh/sshd_config.d/50-whotyped.conf` and reloads sshd |
| `whotyped_sshd_loglevel` | `VERBOSE` | `DEBUG1` only where you accept the log volume |
| `whotyped_manage_auditd` | `true` | installs auditd if missing, writes `/etc/audit/rules.d/90-whotyped.rules`, runs `augenrules --load` |
| `whotyped_privacy_command_text` | `redacted` | `redacted`, `full`, `none` |
| `whotyped_privacy_hash_usernames` | `false` | |
| `whotyped_webhook_url` | `""` | enables the webhook sink when set |
| `whotyped_freeze_windows` | `[]` | list of `{name, start, end}` |
| `whotyped_allowlist_profiles` | `[]` | names of profiles from `rules/allowlist.yaml` to enable, e.g. `[ansible, vscode-remote]` |
| `whotyped_webhook_format` | `json` | `json`, `slack`, `teams` or `discord` |

The config template is deliberately minimal. If you need options it does not expose, set `whotyped_config_extra` (a dict merged at the top level) or replace the template with your own via `whotyped_config_template`. The authoritative reference for options is `deploy/config.example.yaml`.

## What it changes on the host

- `/usr/bin/whotyped` (package) or `/usr/local/bin/whotyped` (binary)
- `/etc/whotyped/config.yaml` (0640 root:root)
- `/etc/systemd/system/whotyped.service` (binary method only; the package ships its own)
- `/etc/ssh/sshd_config.d/50-whotyped.conf`
- `/etc/audit/rules.d/90-whotyped.rules` (same content and path as `whotyped check --fix`)
- `/var/lib/whotyped/` (state and alerts)

Handlers: `reload sshd` (service `ssh` on Debian family, `sshd` elsewhere), `load audit rules` (`augenrules --load`), `restart whotyped`.

## Remove

There is no uninstall task in the role. Reverse it with:

```sh
systemctl disable --now whotyped
apt remove whotyped || rpm -e whotyped
rm -f /etc/ssh/sshd_config.d/50-whotyped.conf /etc/audit/rules.d/90-whotyped.rules
systemctl reload ssh || systemctl reload sshd
augenrules --load
```
