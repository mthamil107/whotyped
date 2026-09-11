# Contributing to whotyped

Thanks for helping. The most useful contributions, in order: false-positive reports with the `reasons` block, new agent fingerprints in the rule pack, log fixtures from distros or OpenSSH versions we do not have, and integrations you actually run.

## Ground rules

- Plain Go, `CGO_ENABLED=0`, Go 1.26. The only dependency is `gopkg.in/yaml.v3`; do not add others without an issue first.
- No telemetry, no network calls except configured sinks. A PR that adds an outbound call without a sink config will be closed.
- Evidence strings must be privacy-redacted (matched fragment, argv0, length; never the full command line unless `privacy.command_text: full`).
- Never re-parse text found inside another record as a log line (log-line injection defence).
- Keep it small and readable. Comments explain why, not what.
- Read `docs/design/ENGINEERING-RULES.md` before touching `internal/`.

## Dev setup

Linux or macOS:

```sh
git clone https://github.com/whotyped/whotyped
cd whotyped
go build ./...
go test ./...
go vet ./... && test -z "$(gofmt -l .)"
```

Windows (PowerShell or Git Bash): the same commands work. The Linux-only readers are behind build tags and have `*_other.go` stubs, so `go build ./...` and `go test ./...` must pass on Windows; parsers are tested with fixtures, not live systems. If you add Linux-only code, add the stub.

Cross-compile check before every PR:

```sh
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
```

Run against real logs without root: `whotyped run --replay testdata/dataset/<case>/events.jsonl --dry-run`. Run the offline simulation: `whotyped simulate --offline`.

## Add your agent (good first issue)

The rule pack is YAML in `rules/agents.yaml` (schema `whotyped.rules.v1`). Adding an agent is one entry plus evidence. Use the "Add agent rule" issue template if you want to discuss first, or open the PR directly.

Example entry (fields from `internal/rules/types.go`):

```yaml
agents:
  - id: example-agent            # lowercase-hyphen, also the AI_AGENT value
    display: Example Agent
    vendor: Example Inc
    process_names: [example-agent, exagent]      # comm or basename(exe)
    argv_contains: ["@example/agent-cli/"]       # for node/python launched CLIs
    env_vars: [EXAMPLE_AGENT, EXAMPLE_AGENT_SESSION]   # NAME or NAME=value
    env_ai_agent: [example-agent, example]       # AI_AGENT values that map here
    skip_flags: ["--auto-approve", "--no-confirm"]
    api_hosts: [api.example.com]
    ssh_banners: ['^SSH-2\.0-exampleclient_']    # only if it has its own SSH client
    tool_wrappers: ["bash -lc"]
    notes: "Sets EXAMPLE_AGENT=1 in every child shell (documented)."
    references:
      - https://docs.example.com/agent/environment
```

Checklist for the PR:

1. Every `process_names`, `env_vars` and `skip_flags` value has a reference URL (vendor docs or source file) or is marked `UNVERIFIED` in `notes`. We prefer fewer, verified fields over many guesses.
2. `whotyped rules validate rules/` passes.
3. Add a fixture: a `proc.seen` or `audit.execve` event line in `testdata/dataset/` (see the existing cases and `lab/README.md` for the format) with an `expected.json`, or a `testdata/procfs/` snapshot if you have one from a real run.
4. Short names (`q`, `agent`) collide with other software. If your agent's binary is a short common word, say so in `notes` and add `argv_contains` or `env_vars` so it does not match alone.
5. If the agent has documented skip/auto-approve flags, include the exact spelling; those feed the Sigma and Falco rules too (`deploy/sigma/`, `deploy/falco/`), which you may update in the same PR.

Banner (`rules/banners.yaml`), style (`rules/styles.yaml`) and API host (`rules/apihosts.yaml`) entries follow the same pattern; allowlist profiles go in `rules/allowlist.yaml` with a `description` that names the tool they are for.

## Reporting a false positive

Use the "False positive" issue template. Paste the full alert line from `alerts.jsonl` (redact `user`, `src_ip`, `key_fingerprint` and `host` if you need to; keep `reasons` and `suppressed` intact) and tell us what the session actually was. We aim to answer within 14 days and to ship a profile or weight change in the next patch release.

## Fixtures from your systems

Log lines from OpenSSH versions, distros or PAM configurations we do not have are valuable. Redact usernames, hostnames, IPs and fingerprints (keep the shape: `alice`, `203.0.113.5`, `SHA256:AAAA…`) and drop them in `testdata/sshlog/` or `testdata/auditd/` with a file name that says the version (`ubuntu-24.04-openssh-9.6-verbose.log`).

## Pull requests

- One topic per PR. Rule-pack changes separate from code changes when practical.
- Fill in the PR template. Say how you tested it and on what.
- CI must be green: build, tests, vet, gofmt, cross-compile, `sigma check` for Sigma changes, `helm lint` for chart changes.
- Review SLA: first response within 5 working days; rule-pack PRs usually faster. If you hear nothing after 7 days, comment on the PR to nudge.
- Two maintainer approvals for changes to frozen contracts and scoring weights; one for everything else (see `GOVERNANCE.md`).

## DCO sign-off

We use the Developer Certificate of Origin (https://developercertificate.org). Every commit needs a `Signed-off-by:` line with your real name and email:

```sh
git commit -s -m "rules: add example-agent fingerprint"
```

By signing off you certify that you wrote the change or have the right to submit it under Apache-2.0. No CLA.

## Style

Commit messages: `area: short imperative summary` (`sshlog: accept sshd-auth identifier`, `docs: fix AcceptEnv example`). Wrap the body at 72 columns and say why. Docs are plain English, short sentences, no marketing.

## Where to ask

Open a discussion or an issue. Security problems go through `SECURITY.md`, not the tracker.
