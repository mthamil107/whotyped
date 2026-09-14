# Helm chart: whotyped DaemonSet

Runs whotyped on every Kubernetes node to watch **SSH sessions to the nodes themselves**. It does not (yet) classify `kubectl exec` sessions into pods; those have no sshd login, `auid=unset`, and need the container-runtime join keys described in `docs/research/03-ssh-auditd-proc.md` §7. That is planned for a later release and will use the same DaemonSet.

Status: chart renders with `helm template`; UNTESTED on a live cluster as of 2026-09-11. No container image is published yet; build one from the release binary and set `image.repository` in `values.yaml`.

## Install

```sh
helm install whotyped deploy/helm/whotyped \
  --namespace whotyped --create-namespace \
  --set config.sinks.webhook.enabled=true \
  --set config.sinks.webhook.url=https://hooks.slack.com/services/XXX
```

## What it mounts and why

| Host path | Mount | Mode | Why |
|---|---|---|---|
| `/proc` | `/host/proc` | ro | with `hostPID: true` the container's own `/proc` already shows node processes; the explicit mount is for tooling that needs a stable root path |
| `/var/log` | `/var/log` | ro | `auth.log` / `secure` when journald is not used |
| `/var/log/audit` | `/var/log/audit` | ro | auditd's `audit.log` (auditd must run on the node; it cannot run in a container) |
| `/run/systemd/journal` | same | ro | `journalctl` socket and files for sshd lines |
| `/etc/machine-id` | same | ro | journalctl needs it to find the journal directory |
| `/var/lib/whotyped` | same | rw | `alerts.jsonl` and `state.json`, persisted on the node |

The container runs as root with `SYS_PTRACE` and `DAC_READ_SEARCH` (for other users' `/proc/<pid>/environ` and the root-only audit log) and drops everything else. `hostNetwork` is off. `readOnlyRootFilesystem` is on. The pod does not talk to the Kubernetes API; its service account token is not mounted.

## Node prerequisites

The chart does not change sshd or auditd on the node. Apply `LogLevel VERBOSE`, `AcceptEnv AI_AGENT AI_AGENT_*` and the audit rules with your node provisioning (the Ansible role in `deploy/ansible/` does it, or your image builder). Without them the DaemonSet runs with reduced coverage, and `kubectl logs` will show `whotyped check` findings at start.

Bottlerocket, Talos and other immutable node OSes: no sshd in the usual sense, so this chart is not useful there.

## Metrics

The `prometheus` sink listens on `0.0.0.0:9477` by default and is exposed as the `metrics` container port with `prometheus.io/*` annotations. Create your own `ServiceMonitor` or `PodMonitor` if you use the Prometheus Operator.

## Values

See `values.yaml`. The `config` block is rendered verbatim to `/etc/whotyped/config.yaml`; the reference for its options is `deploy/config.example.yaml`. Changing `config` rolls the DaemonSet through the `checksum/config` annotation.
