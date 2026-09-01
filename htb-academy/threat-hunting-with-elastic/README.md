# 🟢 HTB Academy — Introduction to Threat Hunting & Hunting With Elastic

**Module:** Introduction to Threat Hunting & Hunting With Elastic (#214) · **Status:** 100% complete · **Track:** Threat Hunting

> Skills-assessment answers are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module is the shift from reactive to proactive defense: instead of waiting for a SIEM alert, a threat hunter builds a testable hypothesis and goes looking for attacker behavior that hasn't tripped anything yet. It covers the 8-stage hunting lifecycle, the Pyramid of Pain (why hunting at the TTP level hurts an attacker far more than blocking an IP ever will), and the three tiers of threat intelligence — strategic, operational, and tactical. The core of the module is a full end-to-end hunt against a threat intel report for a fictional group called Stuxbot: starting from a handful of IOCs (URLs, hashes, C2 IPs), the hunt reconstructs an entire intrusion chain using nothing but KQL queries against Sysmon and Windows event data in the Elastic Stack — from an initial phishing download all the way through to Active Directory enumeration and lateral movement. It closes with an independent skills assessment covering lateral tool transfer, registry persistence, and PowerShell remoting detection.

---

## Files in this folder

| File | Description |
|---|---|
| [`ThreatHunting_Walkthrough.pdf`](./ThreatHunting_Walkthrough.pdf) | Full illustrated walkthrough — the hunting lifecycle, the complete Stuxbot hunt sequence, and the reconstructed attack timeline. KQL/Sysmon reference on the last page. |
| [`ThreatHunting_Student_Notes.pdf`](./ThreatHunting_Student_Notes.pdf) | Condensed study notes with a KQL & Sysmon quick index on the first page. |

Both documents share the same green / pink accent pair used throughout this folder.

---

## Complete walkthrough

### Why hunting exists, and the process behind it

The median dwell time for an attacker inside a compromised network is measured in weeks — by the time a traditional reactive control fires an alert, persistence is often already established. Threat hunting closes that gap through an 8-stage cycle: setting the stage (enable logging, configure tooling, review intel), formulating a testable hypothesis, designing the hunt (data sources, tools, custom queries), gathering and examining data iteratively, evaluating whether the hypothesis held up, mitigating anything found, documenting after the hunt, and feeding lessons into the next one. Hunting isn't purely proactive, either — it runs *simultaneously* with incident response, with IR containing a known threat while hunters search for anything connected to it that hasn't surfaced yet.

### The Pyramid of Pain

The module frames prioritization around one idea: not all indicators cost an attacker the same to lose. A file hash is trivial to change (one byte flip). An IP address is barely more expensive. But TTPs — the actual tactics, techniques, and procedures an attacker relies on — are tough to change without rebuilding their entire operation. Hunting at the TTP level, rather than chasing individual IOCs, is what actually disrupts an adversary instead of just inconveniencing them for an afternoon.

### The Stuxbot hunt, step by step

The hunt starts from a threat intel report on "Stuxbot," a cybercrime group motivated by espionage rather than ransomware, with a known initial-access pattern: phishing email → OneNote attachment → embedded batch file → PowerShell → RAT. Working from that report's IOCs (staging URLs, C2 IPs, file hashes), the hunt runs eleven KQL queries in sequence, each one following directly from the last: find the OneNote file's download event, confirm it landed on disk (its Zone.Identifier confirms it came from the internet), confirm OneNote actually opened it six seconds later, find the child process it spawned (`cmd.exe` running a batch file from a temp folder), trace that batch file to a PowerShell process pulling a staging script from Pastebin, and follow that PowerShell process's activity — file drops, a DNS query for an `ngrok.io` tunneling domain, and a dropped executable that goes on to run SharpHound (Active Directory enumeration) twice and drop further payloads. Searching that payload's hash across the entire environment reveals it landed on a second machine too, confirming lateral movement, and a final query against Windows logon events shows a service account (`svc-sql1`) with failed admin logon attempts followed by successful ones — the exact account compromise pattern that also shows up independently in the SIEM Fundamentals module's own Eagle-environment dataset.

Sysmon event IDs do the heavy lifting throughout: Event 1 (process creation) tracks the parent-child chain, Event 3 (network connection) catches the C2 traffic, Event 11 (file create) catches the dropped files, Event 15 (FileCreateStreamHash) is what actually flags the original browser download, and Event 22 (DNS query) catches the `ngrok.io` resolution that gives the C2 channel away.

### Skills assessment

The independent assessment applies the same hunting discipline to three separate techniques without a guided walkthrough: lateral tool transfer (MITRE T1570, tools copied to a shared public folder), registry-based persistence (T1547.001, a Run key autostart entry), and PowerShell Remoting used for lateral movement toward the domain controller. The specific field values are masked in the documents above per HTB's guidance, but the technique and reasoning path for each is laid out in full.

### Key takeaways

Dwell time is the enemy, and proactive hunting is the direct answer to it. Every hunt in this module follows the same discipline — download, open, child process, network activity, persistence, lateral movement — and a `Zone.Identifier` on a file, a DNS query for `ngrok.io`, or a `SharpHound.exe` process are all high-value tells worth building detections around directly, rather than waiting to encounter them again by accident.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
