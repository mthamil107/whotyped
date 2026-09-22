# Roadmap

Status 2026-09-22. v0.1.0 released 2026-09-21. One real-server pilot (2026-09-14, `docs/research/06-pilot-2026-09-14.md`). Zero stars, forks and watchers; no known external users. One maintainer, working evenings.

This file is the plan of record. Where it disagrees with an older document, this one wins.

## The strategy in one line

Honest agents should say who they are; whotyped is what notices the ones that don't. Lead with the convention, keep the detector as its reference implementation.

Why: several funded vendors are building agent detection on endpoints, and Teleport added agent risk scoring for SSH sessions in July 2026, so detection at the SSH layer is no longer uncontested. Nobody else has published an SSH-side *declaration* convention. A convention spreads through other people's projects, ages better than detection rules, and makes detection stronger: once honest tools announce themselves, silence becomes information instead of the default.

## Now

**N1. Make declaration possible without vendor cooperation.**
The spec currently says OpenSSH cannot forward a local variable. That is wrong: `SendEnv` does exactly that, and the major agent CLIs already set a marker in the shells they spawn (`CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_SANDBOX`). So an operator can declare today with one line of `~/.ssh/config` on the client and one `AcceptEnv` line on the server, with no vendor involvement at all. This is the cheapest adoption lever the project has and it was missed.

- Correct section 7 of the spec and add a client-configuration appendix covering `SendEnv`.
- Teach the sshrc hook and the log reader to accept the vendor markers, not only `AI_AGENT`, and map them to an agent name.
- Spec v0.2: mark `@version` as not recommended toward untrusted hosts (the first adopter's objection, and he was right), add an adopter FAQ answering the safety question he had to measure himself, and take a position on the `AGENT` versus `AI_AGENT` naming debate rather than being welded to one name.

Exit: a user running any of those CLIs can make their sessions self-declare by editing two config files, documented end to end.

**N2. Land the first adopter.**
`tufantunc/ssh-mcp#227` is open with the maintainer's agreement already on record. Its CI is held pending first-contributor approval. After it merges, offer the same one-field change to `bvisible/mcp-ssh-manager` (ssh2, ~480 stars, active) and at most two smaller ones. The Go server named in earlier research no longer exists and one Python server has been dead since April 2025; the nine-server campaign was never real.

Exit: one merged adopter, listed in the spec's compatibility table.

**N3. False-alarm baseline, running in the background.**
Not a gate on N1 or N2. It needs other people's hosts, which do not exist yet, so it starts when the first one is offered.

Minimum honest design, because a weak version of this number is worse than none:
- At least two hosts administered by someone other than the author, auditd enabled.
- Count tracks and sessions, not only alerts, so there is a denominator.
- Every event at `info` or above labelled by that host's own admin.
- The author's own agent traffic tagged with a declaration and reported separately.
- Publish per-clue firing rates on human tracks, so `rhythm.think_time` is judged on data.
- Report as "N false alerts per M human tracks on hosts of type X", with an interval, not a bare number.

Exit: that number published, and `rhythm.think_time` confirmed, retuned or dropped.

**N4. Distribution and hygiene.**
Two release assets have been downloaded, both by the author. Being installable is not the same as being reachable: add `go install` instructions, record the demo the README still promises, and decide whether an apt or COPR repository is worth the maintenance. Review Dependabot PR #1. Finish the trademark check at TMview and WIPO. Update the FAQ's Teleport comparison for their July 2026 agent controls. Advertise the rule-pack reviewer role from GOVERNANCE in the adopter conversations, since a second maintainer is most likely to come from there.

## Next, on request rather than on schedule

**Command text without auditd.** Today a remote agent without an auditd rule tops out at `info`. The cheap route is the kernel's process-event connector plus an immediate read of the new process's command line: pure Go, no BTF or kernel-version dependency. eBPF is the textbook answer and also a multi-month rewrite that trades auditd friction for BTF friction; the pilot host could not have run it. Defer until a user asks.

**Other doors in.** AWS SSM session logs, whose process chain is already documented. `kubectl exec` after that. Not `docker exec`.

**Sigma upstream.** Submit the auditd rules to SigmaHQ once they have field use behind them.

## Cut

Not deferred, cut, so the list stays honest:

- **Keystroke and paste timing.** The pilot had no interactive sessions on either side, so there is nothing to calibrate against; it needs session recording almost nobody runs; and the FAQ already concedes timing signals are forgeable. It is the weakest signal and the most work.
- **Windows servers.** The README already says there is no Windows target.
- **A central dashboard.** `whotyped report` over the JSON file, shipped through syslog or Wazuh, already is one.
- **Enforcement or blocking.** Monitor-only is why the daemon is installable at all.
- **Any hosted service.** Data leaving the server is the fastest way to be refused. This retires the "hosted rules feed" idea from the original plan.

## How success is measured

| Horizon | The number that matters | Obtainable without telemetry |
|---|---|---|
| Now | tools and hosts that declare, whether through an adopter or `SendEnv` | yes, from adopter repositories and reports |
| Now | release asset downloads and unique clones per week | yes, GitHub traffic API |
| Next | false alerts per human track, from someone else's hosts | yes, from pilot reports |
| Later | a deployment described by the person running it, not by the author | yes |

Stars are not a goal, but zero stars is a discoverability problem when recruiting pilot hosts, so it is worth watching as a symptom.

The targets table in the old launch playbook (800 stars, 15 interviews, 3 signed pilots) is retired. It was written before there was a released tool, and nothing in it is a commitment.

## Risks

- **No human baseline.** The pacing clue is tuned on three real agent sessions from one host. It may not survive a busy real fleet. N3 is the answer, and until it lands the clue stays marked provisional.
- **Evasion.** A careful agent can look human. The convention, not better heuristics, is the durable answer.
- **The convention is copyable.** Anyone can adopt the idea and drop the origin. That is a success, not a loss, as long as the variable name stays compatible.
- **Single maintainer.** Documented in GOVERNANCE. The most likely second maintainer is someone met through an adopter.
- **Vendors ship the feature.** Likely. The answer is to be the convention they implement rather than the product they replace.
