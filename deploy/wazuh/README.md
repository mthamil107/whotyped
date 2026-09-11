# Wazuh integration

Files:

- `ossec.conf.snippet.xml`: `<localfile>` block for the agent, reads `/var/lib/whotyped/alerts.jsonl` as JSON.
- `local_rules.xml`: rules 100500 to 100510 on the manager.
- `local_decoder.xml`: only for syslog-wrapped whotyped lines.

Status: written against Wazuh 4.x syntax and the `whotyped.alert.v1` schema. UNTESTED on a live manager as of 2026-09-11; the `not_same_field` composite (100509) in particular needs a Wazuh release that supports it (4.x; verify on yours). Please open an issue with `wazuh-logtest` output if something does not fire.

## Install

On each monitored host (Wazuh agent):

1. Append the `<localfile>` block from `ossec.conf.snippet.xml` to `/var/ossec/etc/ossec.conf`.
2. Make the file readable by the agent: `usermod -aG whotyped wazuh` (group name per your install) or set the whotyped file mode in its config.
3. `systemctl restart wazuh-agent`.

On the manager:

1. `cp local_rules.xml /var/ossec/etc/rules/whotyped_rules.xml`
2. If you use the syslog path: `cp local_decoder.xml /var/ossec/etc/decoders/whotyped_decoder.xml`
3. `systemctl restart wazuh-manager`

## Test

Paste one alert line into `/var/ossec/bin/wazuh-logtest`:

```
{"schema":"whotyped.alert.v1","ts":"2026-09-11T14:03:22Z","host":"web-03","event":"agent_detected","class":"suspected_agent","mode":"remote_agent","user":"alice","src_ip":"10.0.0.5","key_fingerprint":"SHA256:Qm3k","agent":"","score":82,"level":"alert","reasons":[{"clue":"rhythm.burst","category":"rhythm","weight":20,"evidence":"14 exec channels in 92s"}],"suppressed":[],"session_id":"tr_9f31c2a7b8e4","connections":1,"window":{"start":"2026-09-11T13:50:00Z","end":"2026-09-11T14:05:00Z","execs":14},"freeze_window":null,"actions_hint":"Ask alice whether an AI tool is driving this key."}
```

Expected: decoder `json`, rule 100503, level 10. Change `"level":"alert"` to `"level":"high"` and `"event"` to `agent_high` to get 100504 (level 12); `freeze_violation` gives 100505 (level 13).

## Rule map

| Id | whotyped event / level | Wazuh level | Meaning |
|---|---|---|---|
| 100500 | any (json decoder) | 0 | base |
| 100510 | any (syslog decoder) | 0 | base |
| 100501 | `agent_declared` | 5 | agent announced itself via `AI_AGENT` |
| 100502 | `agent_detected`, level `info` | 5 | score 40 to 69 |
| 100503 | `agent_detected`, level `alert` | 10 | score 70 to 89 |
| 100504 | `agent_high` or `agent_detected` at level `high` | 12 | score 90+ |
| 100505 | `freeze_violation` | 13 | agent activity inside a freeze window |
| 100506 | `agent_still_active` | 7 | re-alert, at most every 30 min |
| 100507 | `agent_ended` | 3 | track expired |
| 100508 | 3x 100503 same `user` in 1 h | 12 | repeated |
| 100509 | 2x 100503 same `user`, different `host` in 1 h | 12 | multi-host |

Levels 10 and above trigger Wazuh's default email and active-response hooks; tune to taste.

## Field notes

- The json decoder exposes `reasons` as a flattened array; searching for a specific clue works with `data.reasons.clue: rhythm.burst` in the dashboard (exact path depends on your indexer mapping).
- `score` is a string after decoding. Match ranges with `type="pcre2"` regexes if you need them; the `level` field already encodes the thresholds.
- `user` and `src_ip` are copied into the description so that dashboards show them without expanding the event. If you enable `privacy.hash_usernames` in whotyped, `user` is a hash and the descriptions will show that hash.
