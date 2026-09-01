# 🟠 HTB Academy — Incident Handling Process

**Module:** Incident Handling Process · **Status:** 100% complete · **Track:** SOC / Incident Response

> Lab-specific answers (usernames, hashes, IPs, file paths tied to this exact environment) are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module teaches the formal NIST incident-handling lifecycle — preparation, detection and analysis, containment/eradication/recovery, and post-incident activity — and how it maps onto the Cyber Kill Chain and MITRE ATT&CK. It covers the practical side too: what belongs in a jump bag, what documentation and protective measures a SOC needs in place before an incident ever happens, and how to run an IOC-driven investigation without tipping off an attacker through piecemeal containment. The module's centerpiece is a full breach case study — "Insight Nexus," a mid-sized firm compromised by two unrelated threat actors at once — that has to be reconstructed from Sysmon and Windows Security event log evidence. It closes with a skills assessment worked entirely inside TheHive, HTB's open-source case management platform, simulating what a Tier 1/2 analyst actually does once a case is opened: enrichment, role assignment, prioritization, and answering targeted forensic questions.

---

## Files in this folder

| File | Description |
|---|---|
| [`Incident_Handling_Walkthrough.pdf`](./Incident_Handling_Walkthrough.pdf) | Full illustrated walkthrough, including the complete Insight Nexus case study and kill-chain reconstruction. Frameworks quick reference on the last page. |
| [`Incident_Handling_Student_Notes.pdf`](./Incident_Handling_Student_Notes.pdf) | Condensed study notes with a frameworks & event-ID index on the first page. |

Both documents share the same orange / sky-blue accent pair used throughout this folder.

---

## Complete walkthrough

### The NIST incident-handling lifecycle

Everything in this module sits inside four cyclic phases: **preparation** (build IH capability, write policies, train the team), **detection & analysis** (monitor via sensors/logs/SIEM, triage, build a timeline), **containment, eradication & recovery** (stop the spread, remove the root cause, restore operations), and **post-incident activity** (final report, lessons learned, updated playbooks). It's explicitly not linear — new evidence found during detection can loop a handler back to earlier phases, and handlers spend the majority of their time in preparation and detection rather than the more dramatic-sounding containment phase.

### Cyber Kill Chain and the Pyramid of Pain

The seven-stage Cyber Kill Chain (reconnaissance, weaponize, deliver, exploit, install, command & control, action on objectives) frames how an intrusion actually unfolds, and attackers loop back to reconnaissance after gaining a foothold to find new targets — the earlier in the chain a defender can interrupt them, the better. The **Pyramid of Pain** is the reasoning behind why MITRE ATT&CK-based detection is worth building: indicators like file hashes and IP addresses cost an attacker almost nothing to change, but detecting their actual TTPs (tactics, techniques, procedures) forces a fundamental change in how they operate — which is far more disruptive than any blocklist.

### Preparation: documentation, the jump bag, and protective measures

Before an incident happens, a SOC needs incident-response policies, up-to-date network diagrams and golden-image baselines, and a "jump bag" — a forensic workstation, disk-imaging and memory-capture tools, write blockers, and chain-of-custody forms, kept ready to go and completely independent of the organization's own network (because during a real incident, you have to assume the whole domain might be compromised). On the protective-measures side, the module covers DMARC (blocking spoofed email), endpoint hardening (LAPS, constrained-language PowerShell, blocking script execution from user-writable folders), enforced MFA on all admin access, continuous vulnerability scanning, and purple-team exercises where a red team attacks while informing the blue team, specifically to test whether logging, alerting, and the IR playbook actually work in the real environment.

### Detection, IOCs, and the investigation loop

Detection can come from an employee report, a security tool alert, proactive threat hunting, or a third party — and it should be layered across the network perimeter, the internal network, endpoints, and the application layer. Once something is detected, investigation follows a three-step loop: create and use IOCs (documented in formats like OpenIOC, YARA, or STIX/JSON), identify new leads by triaging IOC hits and cutting false positives, then collect and analyze data — preferring live response over shutting a system down, since volatile RAM evidence is lost the moment power goes. One sharp caution from the module: never cache privileged credentials on a system that might be compromised. WinRM's Network Logon type doesn't cache credentials remotely; PsExec run with explicit credentials does — a distinction that matters a lot when you're actively investigating a live intrusion.

### Containment, eradication, recovery, and the report that follows

Containment splits into short-term (isolate to a VLAN, pull the cable, sinkhole the C2 domain — minimal footprint, preserve everything for forensics) and long-term (rotate passwords, apply firewall rules, patch, notify stakeholders) — and every containment action across every affected system has to happen simultaneously, because a piecemeal response tips off the attacker. Eradication means the root cause is *fully* eliminated, not just the obvious symptom — a lesson the module drives home hard in its case study. The final incident report has to cover what happened, how the team performed against its own playbooks, what containment actions were taken, and what should change going forward; it's not just paperwork — it's admissible in legal proceedings, drives budget decisions, and trains the next new analyst who joins the team.

### Case study: the Insight Nexus breach

The module's capstone reconstructs a real-feeling breach at a fictional firm, Insight Nexus, using nothing but event log evidence. Two threat actors were active concurrently: **Crimson Fox**, a state-backed APT after long-term persistence and data theft, and **Silent Jackal**, an opportunistic low-skill group that defaced a web portal almost incidentally. Crimson Fox's chain runs from default credentials on an internet-facing ManageEngine console, through a Java RCE that opened outbound C2 over HTTPS, to AD enumeration that found an exposed RDP host, lateral movement onto that host, access to a file share containing client project data, a GPO-pushed disguised MSI installer for domain-wide persistence, and finally exfiltration of an archived zip over HTTPS. The whole chain has to be pieced together from Sysmon network-connection and process-creation events plus Windows 4624 logon events — and the module's sharpest lesson is that finding and deleting Silent Jackal's obvious defacement marker did nothing to address Crimson Fox's actual root cause. Treating the easy, visible finding as "the incident" would have missed the real breach entirely.

### Skills assessment — working the case in TheHive

The closing assessment moves the whole investigation into TheHive: creating a case, linking tagged alerts, assigning roles (Triage Analyst, Forensics Lead, Containment Lead, Comms Lead), enriching indicators through VirusTotal, and setting case priority to Critical once data exfiltration is confirmed. The specific forensic answers — which process spawned a credential-dumping tool, which external IP received the exfiltrated archive, which user's account was used for lateral movement — are exactly the kind of targeted questions a Tier 1/2 analyst has to answer under a real case, and they're masked in the documents above per HTB's guidance, but the reasoning path to each one is laid out in full.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
