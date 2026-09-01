# 🔷 HTB Academy — Security Monitoring & SIEM Fundamentals

**Module:** [Security Monitoring & SIEM Fundamentals (#211)](https://academy.hackthebox.com/module/details/211) · **Status:** 100% complete · **Track:** SOC Analyst / Blue Team

---

## What this lab was about

This module is HTB Academy's introduction to working inside a real SIEM as a SOC Tier 1 analyst. It starts from first principles — what a SIEM actually does, how the Elastic Stack (Elasticsearch, Logstash, Kibana, Beats) turns raw logs into searchable data, and where a SOC analyst sits in the bigger picture of tiers and escalation paths. From there it moves into hands-on work: writing KQL queries against Windows Security event logs, building four detection dashboards in Kibana from scratch, and mapping detections to the MITRE ATT&CK framework. The module closes with a full skills assessment that simulates a first day on the job — reviewing seven live dashboard findings and making real triage calls (nothing suspicious, consult IT operations, or escalate) for a fictional company called Eagle. It's less about memorizing SIEM theory and more about building the judgment a Tier 1 analyst needs to separate noise from a real incident.

---

## Files in this folder

| File | Description |
|---|---|
| [`SIEM_Fundamentals_Walkthrough.pdf`](./SIEM_Fundamentals_Walkthrough.pdf) | Full illustrated walkthrough — diagrams, dashboard configs, and the reasoning behind every triage decision. Commands/queries reference on the last page. |
| [`SIEM_Fundamentals_Student_Notes.pdf`](./SIEM_Fundamentals_Student_Notes.pdf) | Condensed study notes, organized the same way I'd want them open in a second monitor. Command & query index on the first page for fast lookup. |

Both documents share the same blue accent color used throughout this folder.

---

## Complete walkthrough

### 1. What is a SIEM?

A Security Information and Event Management (SIEM) platform collects logs from across an entire environment, normalizes them into a common format, correlates events across sources, and raises alerts when suspicious patterns appear. It's the central hub of a SOC — every alert, investigation, and escalation decision flows through one.

**How a log travels through a SIEM:** data ingestion (firewalls, endpoints, servers, IDS/IPS, apps, cloud) → normalization into a common schema (ECS in the Elastic Stack) → aggregation of related events → correlation against detection rules and threat intel → alerting, where an analyst is notified and triage begins.

SIEMs evolved in three generations: **SIM** (log storage and reporting, no real-time detection), **SEM** (real-time correlation, no storage), and modern **SIEM** (both, combined). SOC maturity follows a similar arc — from **SOC 1.0** (network-centric, siloed tools) to **SOC 2.0** (intelligence-driven, proactive) to an emerging **Cognitive SOC** (AI-augmented, behavioral analytics).

### 2. The Elastic Stack

The Elastic Stack is the most widely deployed open-source SIEM platform, and the one this module uses hands-on:

- **Elasticsearch** — the storage and search engine. Every log becomes a JSON document, distributed and searchable via a RESTful API.
- **Logstash** — the ingestion pipeline. Collects logs, transforms/enriches them, and forwards them to Elasticsearch.
- **Kibana** — the analyst-facing UI. This is where the actual work happens: Discover for raw search, Dashboards and Lens for building visualizations, KQL for querying.
- **Beats** — lightweight agents installed directly on endpoints (Filebeat for log files, Winlogbeat for Windows events) that ship data upstream.

The full production pipeline is `Beats → Logstash → Elasticsearch → Kibana`. Smaller environments often skip Logstash and ship Beats directly to Elasticsearch. All of it speaks a shared vocabulary called the **Elastic Common Schema (ECS)** — field names like `event.code`, `user.name`, and `@timestamp` that stay consistent no matter which system the log originated from, which is what makes a single KQL query work across Windows, Linux, network, and cloud data.

### 3. SOC roles, tiers & MITRE ATT&CK

The module lays out the standard SOC tier structure: **Tier 1** analysts monitor and triage (speed matters most), **Tier 2** investigators do deep-dive analysis and tune detection rules, and **Tier 3** experts handle the most complex incidents and proactive threat hunting. Detection engineers write and maintain the rules everyone else relies on; incident responders take over once something is confirmed.

Every detection in this module gets mapped to **MITRE ATT&CK** — a public knowledge base of real adversary behavior. A **tactic** is the attacker's goal (the "why"), a **technique** is how it's achieved (the "what"), and a **sub-technique** is a specific variation. The module's running example is MSBuild abuse: an Office application spawning `MSBuild.exe` is a classic Living-off-the-Land Binary (LoLBin) pattern — mapped to `TA0005` Defense Evasion / `TA0002` Execution, technique `T1127` (Trusted Developer Utilities Proxy Execution), sub-technique `T1127.001` (MSBuild specifically), and rated high severity because legitimate use of that pattern is rare.

### 4. Writing KQL queries

KQL (Kibana Query Language) is how you search and filter in Kibana's Discover tab and in visualization filters — `field:value` for exact matches, `AND`/`OR`/`NOT` for logic, `*` for wildcards, and comparison operators for ranges. Every query written during the module targets Windows Security event logs, for example: `event.code:4625` to find every failed logon, narrowed with `AND winlog.event_data.SubStatus:0xC0000072` to isolate attempts against **disabled accounts specifically** — a strong indicator that someone still holds valid credentials for an account that should no longer work. The one rule that trips up almost everyone starting out: use the plain field name (`user.name`) in KQL filters, but the `.keyword` suffix (`user.name.keyword`) when that field is used as a Row or Column in a Kibana Lens aggregation.

### 5. Windows Security Event IDs

The module builds fluency with the Windows Security event IDs a SOC analyst needs memorized: `4624` (successful logon), `4625` (failed logon), `4648` (explicit-credential logon — a pass-the-hash indicator), `4672` (special privileges assigned), `4720` (account created), `4728`/`4732`/`4756` (added to a security group at various scopes), `4733` (removed from a group), and `4740` (account locked out). For failed logons specifically, the `SubStatus` code tells you *why* it failed — `0xC0000072` (account disabled) and `0xC0000064` (username doesn't exist) are high-value detection triggers, while `0xC0000193`/`0xC0000071` (expired account/password) are usually just noise.

### 6. Building the four Kibana dashboards

Four detection dashboards were built from scratch using the same repeatable Kibana Lens workflow (create visualization → set index pattern `windows*` → filter on the relevant event code → switch chart type to Table → add fields as Rows with `.keyword` → Count as the metric → save):

1. **Failed logon attempts (all users)** — filtered to `event.code:4625`, excluding computer accounts. Surfaced `sql-svc1` with unusual failed logins → consulted IT Operations, since service accounts shouldn't normally fail authentication.
2. **Failed logon attempts (disabled users)** — added the `0xC0000072` SubStatus filter. Found user `anni` attempting to authenticate on a disabled account → escalated, since that means someone still has (or is guessing at) valid credentials for an account that was deliberately turned off.
3. **Successful RDP logons for service accounts** — filtered `event.code:4624` with `winlog.logon.type:RemoteInteractive` and `user.name:svc-*`. Found `svc-sql1` RDPing into the PKI server from `192.168.28.130` → escalated, since service accounts in this environment run local processes only and should never RDP anywhere.
4. **Group membership changes on Administrators** — filtered `event.code:4732 OR 4733` with an absolute time range. Found an unrecognized SID added to Administrators on 2023-03-05 → consulted IT Operations, since it could plausibly be legitimate admin work but needed confirmation before treating it as a compromise.

### 7. Alert triage & the skills assessment

Every alert resolves to one of three decisions: **nothing suspicious** (explained by normal, expected behavior), **consult IT Operations** (plausibly legitimate, but needs more context before a call can be made), or **escalate to Tier 2/3** (a clear indicator of compromise, or a high-risk event with no benign explanation).

The closing skills assessment applies this against a defined environment (cloud-only org, four IT admins, a Privileged Access Workstation policy, `svc-` prefixed service accounts, root SSH disabled) across seven findings — from the four dashboards above plus three additional scenarios (admin logins outside the PAW policy, and a root SSH login that directly violates environment policy). Working through all seven is what ties the whole module together: the *technical* skill of building a Kibana visualization is only half the job — the other half is judgment about what a finding means in the specific context of the environment you're defending, which is exactly the kind of reasoning a Tier 1 analyst is hired to demonstrate.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
