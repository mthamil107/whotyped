# Phase 0 interview guide

Goal: 15 interviews with people who run Linux servers (sysadmins, SREs, platform engineers, SOC analysts) before we lock scope for v0.1. We want to learn whether they have the problem, how they would recognise it, and what output they would act on. 30 minutes each. Record with consent, or take notes.

Not a sales call. Do not demo before question 10.

## Screener (2 minutes, by message before booking)

Book if all of these are true:

1. Operates or defends at least 10 Linux hosts reachable over SSH (or a Kubernetes fleet with node SSH).
2. Has root or sudo on those hosts, or triages alerts from them.
3. Has used, or works with people who have used, an AI coding agent (Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI, Aider, Goose) in the last 6 months.

Record: role, team size, host count, distro mix, whether auditd is already running, SIEM in use (Wazuh, Splunk, Elastic, Sentinel, none).

Aim for a spread: 5 SRE/platform, 5 traditional sysadmin, 5 SOC/security. At least 3 in the EU (works-council angle), at least 3 in regulated sectors (payments, health, public sector).

## Questions (25 minutes)

Ask in order. Follow-ups in italics. Do not lead.

1. How often do AI agents run commands on your servers today, as far as you know? *Who runs them? On which hosts? Over SSH, kubectl exec, SSM, something else?*
2. If an agent ran commands on a production host using a colleague's SSH key tomorrow, how would you find out? *Walk me through it. Which log would you open first?*
3. When did you last look at sshd logs or auditd for anything? *What were you looking for?*
4. Tell me about a false alarm that cost you real time. *What made it expensive: volume, timing, the wrong person paged?*
5. What would you actually do if a tool told you "session on alice's key at 14:03 looks like an AI agent, confidence 82"? *Ask alice? Kill the session? Ignore? Who else would you tell?*
6. Do you have change freezes or maintenance windows? *How are they enforced? Would "an agent was active during the freeze" matter?*
7. What already runs as root on your hosts for security or monitoring? *auditd, osquery, Wazuh agent, Falco, CrowdStrike, Datadog, node_exporter?* (List them; this predicts install friction.)
8. Would you install another root daemon for this? *What would it need to be: package, container, static binary? Who has to approve? How long does approval take?*
9. Where do alerts need to land for you to see them? *Slack, PagerDuty, SIEM, email, a file, Prometheus?*
10. Shared or service accounts: how many, and who uses them? *Would knowing "an agent used `deploy`" be useful or noise?*
11. (Show the sample alert JSON and the one-line report.) What is missing, and what would you delete? *Is the score useful or would you prefer a yes/no?*
12. Privacy: would recording the first word of each command and its length be acceptable on your hosts? Full command text? *Who would object? Works council, legal, the team?*

Closing (2 minutes): Would you run a pilot on 5 to 20 hosts for two weeks and share anonymised counts? May we quote you anonymously? Who else should we talk to?

## Scoring sheet

Score each interview 0 to 2 per row right after the call. Total 0 to 16.

| Dimension | 0 | 1 | 2 |
|---|---|---|---|
| Problem exists | no agents on servers, none expected | some, informal | agents on servers weekly or more |
| Blind today | would know quickly via existing tools | partial (would find it in a post-mortem) | would not know |
| Would act | would ignore | would ask the person | has a defined action (kill session, rotate key, ticket) |
| Freeze relevance | no freezes | freezes exist, not enforced | enforced freezes, violation is an incident |
| Install feasibility | new root daemon impossible | possible with approval (weeks) | routine (days) |
| Output fit | none of our sinks | one sink works | SIEM plus chat plus report |
| Privacy fit | full command text unacceptable and redaction not enough | redaction acceptable | no concern |
| Pilot willingness | no | maybe later | yes, named hosts |

Interpretation: 12 or more = design partner candidate; 8 to 11 = launch audience; under 8 = note why and move on.

## Synthesis template

Fill after every 5 interviews, and finally after 15.

```
Interviews: N   Roles: SRE x, sysadmin y, SOC z   Regions: …   Regulated: …

1. How agents reach servers (count per path): laptop agent + ssh __ | MCP SSH server __ | agent installed on host __ | kubectl exec __ | SSM __ | none __
2. Detection today: would know __ | partial __ | blind __
3. Most common "what I would do": …
4. False-alarm pain (quotes): …
5. Freeze windows: enforced __ | informal __ | none __
6. Root daemons already present (top 5): …
7. Preferred delivery: deb/rpm __ | container __ | binary __ | ansible __ | helm __
8. Preferred sinks (ranked): …
9. Privacy: redaction ok __ | full text ok __ | neither __ ; works council mentioned __
10. Reactions to the sample alert: keep …, cut …, add …
11. Pilot commitments: names, host counts, dates
12. Surprises (things we did not expect):
13. Scope changes for v0.1 (decide, with owner):
```

## Logistics

- Slots and status live in `tracker.md`.
- Notes go in `docs/interviews/notes/<id>.md` (not committed if they contain names; keep anonymised versions only).
- Consent line to read out: "We take notes for product research, we will not publish your name or employer, and you can stop at any time."
