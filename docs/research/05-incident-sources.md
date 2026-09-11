# Incident sources for the README "Why" section

Checked 2026-09-11 against the pages listed. "Verified" means the source
states the claim; "softened" means the README wording was changed because
no fetched source supports the original phrasing. Figures that only one
outlet reports are attributed to it in the README ("reports put...").

| Incident | Claim in README | Source URL | Verified |
|---|---|---|---|
| Replit / SaaStr, July 2025 | Replit's coding agent deleted a live production database | https://incidentdatabase.ai/cite/1152 ; https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/ | yes |
| Replit / SaaStr | during a declared code (and action) freeze | Fortune (above); AIID #1152 title | yes |
| Replit / SaaStr | then misrepresented what it had done / whether the data was recoverable | Fortune; AIID #1152 | yes |
| Replit / SaaStr | records for more than 1,200 executives and over 1,190 companies | Fortune | yes |
| Replit / SaaStr | about 4,000 fabricated user records | AIID #1152 (aggregated press headlines: "4,000 fake users"); not in Fortune | yes, single-outlet class; worded "reports put" |
| Replit / SaaStr | "an agent with production credentials" (old wording) | no fetched source uses the phrase; Fortune only implies prod access via the later dev/prod separation fix | no, softened |
| Replit / SaaStr | date July 2025 (incident 2025-07-18, coverage 21-23 July) | AIID #1152; Fortune | yes |
| s1ngularity / Nx, August 2025 | malicious nx releases published 26 August 2025 | https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c (timeline); https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware | yes (last versions fall on 27 Aug UTC) |
| s1ngularity / Nx | post-install script invoked `claude --dangerously-skip-permissions -p`, `gemini --yolo -p`, `q chat --trust-all-tools --no-interactive` | StepSecurity (verbatim strings); https://www.wiz.io/blog/s1ngularity-supply-chain-attack (flags); the Nx advisory itself does not mention the AI CLIs | yes (cite StepSecurity/Wiz, not the advisory) |
| s1ngularity / Nx | wrote an inventory of sensitive file paths to /tmp/inventory.txt and exfiltrated credentials to attacker-created GitHub repos | Nx advisory; StepSecurity | yes |
| s1ngularity / Nx | over a thousand valid GitHub tokens leaked (phase 1) | Wiz, s1ngularity-supply-chain-attack | yes |
| s1ngularity / Nx | over 5,500 private repositories made public (phase 2) | Wiz (same post, 29 Aug update); revised to 6,700+ in https://www.wiz.io/blog/s1ngularitys-aftermath (3 Sep 2025) | yes, marked as later revised |
| GTG-1002, Sep-Nov 2025 | a state-sponsored actor used Claude Code to run most of an intrusion campaign | https://www.anthropic.com/news/disrupting-AI-espionage ; full report https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf | yes |
| GTG-1002 | 80-90% of tactical operations performed by the AI | Anthropic news ("80-90% of the campaign"); full report ("80-90% of tactical operations") | yes |
| GTG-1002 | roughly 30 organisations targeted, a handful of successful intrusions | Anthropic news; full report | yes |
| GTG-1002 | lateral movement and remote command execution via MCP-connected tooling | full report | yes |
| GTG-1002 | "lateral movement over SSH" (old wording) | the string "SSH" does not appear in either Anthropic document | no, removed |
| GTG-1002 | detected mid-September 2025, disclosed 13 November 2025 | Anthropic news; full report | yes |
| Amazon Kiro, December 2025 | Amazon's internal Kiro coding agent, running under an engineer's role with broader permissions than intended, deleted and recreated an environment | https://incidentdatabase.ai/cite/1442/ ; https://www.theregister.com/2026/02/20/amazon_denies_kiro_agentic_ai_behind_outage/ ; https://www.aboutamazon.com/news/aws/aws-service-outage-ai-bot-kiro | yes |
| Amazon Kiro | roughly 13-hour outage of AWS Cost Explorer in one mainland-China region | AIID #1442 and The Register (both relaying the Financial Times, 20 Feb 2026); Amazon confirms the Cost Explorer interruption and the region but gives no duration | yes for the FT-derived figure; attributed |
| Amazon Kiro | Amazon attributes it to a misconfigured role / user error, not the AI | Amazon statement (above); The Register | yes |
| Amazon Kiro | incident December 2025 (about 15 Dec per AIID; "last December" per Amazon); made public 20 February 2026 | AIID #1442; The Register; Amazon | yes |
| Amazon Kiro | AI Incident Database entry number | #1442 (not #1263; #1263 is the GTG-1002 entry) | corrected |

Notes

- The Financial Times article that originated the Kiro story is paywalled
  and was not fetched; every claim about it is taken from The Register and
  AIID #1442, which quote it, and from Amazon's public reply.
- The Nx "5,500 repos" figure is a point-in-time count from Wiz's 29 August
  update; Wiz's 3 September follow-up gives 6,700+ repositories and 480+
  accounts for that phase. The README keeps the earlier figure with a note.
- Nothing in the Anthropic documents names SSH; whotyped's relevance to
  GTG-1002 is that agent-driven lateral movement and remote command
  execution are the shapes it scores, not that the report documents SSH.
