# Governance

whotyped is an Apache-2.0 project. This document says who decides what, and how. It is deliberately short and will grow only when a real situation needs it.

## Roles

**Maintainers** have merge rights on the whole repository and make releases. There must be at least two maintainers at all times; if the count drops to one, recruiting a second is the project's top priority and no major release ships until it is done. Maintainers are listed below.

**Rule-pack reviewers** have merge rights limited to `rules/`, `deploy/sigma/`, `deploy/wazuh/`, `deploy/falco/` and their fixtures. They review agent fingerprints, allowlist profiles and SIEM rules. Becoming one: three merged rule-pack PRs of good quality and a nomination by a maintainer.

**Contributors** are everyone else who has had a PR merged. Contributors are credited in release notes.

Current maintainers:

| Name | GitHub | Since | Areas |
|---|---|---|---|
| Thamil | [handle] | 2026-09 | lead, architecture, releases |
| [second maintainer, to be appointed before v0.1.0] | | | |

Current rule-pack reviewers: none yet.

## How decisions are made

**Lazy consensus** for almost everything. A proposal (issue or PR) that has been open for 72 hours with no objection from a maintainer is accepted. Silence is consent. Objections must say what would resolve them.

**Two maintainer approvals** are required for:

- changes to frozen contracts (`internal/event`, `internal/readers`, `internal/clues`, `internal/session`, `internal/score`, `internal/alert`, `internal/rules` types)
- changes to scoring weights, caps or thresholds
- changes to the alert schema or config schema
- adding a dependency
- anything that changes what data is collected or written (privacy defaults)
- releases
- this document, `SECURITY.md`, the licence

**One approval** (maintainer or, within their area, rule-pack reviewer) for everything else. Authors do not approve their own PRs.

**Disagreement** between maintainers: talk first, in the issue. If it is not resolved in a week, the lead maintainer decides and records the decision and the dissent in the decision log. If the disagreement is about the lead's own change, the other maintainers decide by simple majority.

**Removing a maintainer** requires agreement of all other maintainers, for sustained inactivity (6 months without review or commit activity, after a check-in) or a code-of-conduct violation. Inactive maintainers become emeritus and are welcome back.

## Scope decisions

The project's scope is stated in the README: detection of AI agents acting over SSH on Linux servers, from the server's vantage point, with honest limits. Proposals that move away from that (enforcement, endpoint agents, a hosted service) need an explicit scope discussion, not lazy consensus.

Things we have decided not to do, and why, live in the decision log so that they are not re-litigated every quarter.

## Releases

Semantic versioning. Before 1.0, minor versions may break config and schema with a migration note. Patch releases for fixes and rule-pack updates as often as useful. A maintainer tags, CI builds and signs. Release notes list contributors.

## Security

See `SECURITY.md`. Security fixes may be merged by a single maintainer without the 72-hour wait, with the second review happening after the fact.

## Decision log

Append-only. One line per decision, newest first. Format: date, decision, link, who.

| Date | Decision | Link | By |
|---|---|---|---|
| 2026-09-11 | Alert schema `whotyped.alert.v1` frozen for v0.1; readers, correlator, scorer contracts frozen | `docs/design/ARCHITECTURE.md` | lead |
| 2026-09-11 | Privacy default is redacted evidence, not hashed and not full text | `docs/design/ARCHITECTURE.md` §1.9 | lead |
| 2026-09-11 | No eBPF in v0.1; sshd log + auditd + /proc only | `docs/design/ARCHITECTURE.md` | lead |
| 2026-09-11 | Publish the `AI_AGENT` over SSH convention as a draft standard in this repo and send PRs to MCP SSH servers | `docs/spec/ai-agent-over-ssh.md` | lead |
| 2026-09-11 | Name `whotyped`; use `.io`/`.dev`, `.com` is squatted; manual trademark check before launch | `docs/research/01-name-check.md` | lead |
