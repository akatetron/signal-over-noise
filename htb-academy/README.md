<div align="center">

# ◈ HTB Academy — CDSA Path

**Certified Defensive Security Analyst — learning path**

![Modules](https://img.shields.io/badge/Modules-11-9FEF00?style=flat-square&labelColor=141d2b)
![Status](https://img.shields.io/badge/CDSA-Certified_Sep_2026-9FEF00?style=flat-square&logo=hackthebox&logoColor=black&labelColor=141d2b)

</div>

<br>

Module write-ups from the HTB Academy CDSA path. Each folder contains a full walkthrough
with the reasoning behind every step, plus illustrated PDF walkthroughs and condensed
student notes.

> Graded lab answers are partially masked in line with HTB Academy's guidance on not
> publishing exact answers to currently-active modules. The detection logic and
> methodology behind each are written out in full.

<br>

---

## ▸ Detection & monitoring

| Module | Focus |
|---|---|
| [Security Monitoring & SIEM Fundamentals](./security-monitoring-siem-fundamentals/) | Elastic Stack architecture, KQL, building four detection dashboards, alert triage against a defined environment |
| [Splunk for Security Analysts](./splunk-for-security-analysts/) | SPL fundamentals, correlation searches, Splunk-based investigation workflow |
| [Threat Hunting with Elastic](./threat-hunting-with-elastic/) | Hypothesis-driven hunting, EQL and KQL, hunting without a starting alert |
| [Working with IDS/IPS](./working-with-ids-ips/) | Suricata, Snort 3, Zeek, JA3 TLS fingerprinting, writing rules against real C2 frameworks |

## ▸ Endpoint & DFIR

| Module | Focus |
|---|---|
| [Windows Event Logs & Finding Evil](./windows-event-logs-finding-evil/) | Sysmon telemetry, DLL hijacking, CLR injection, `CreateRemoteThread`, LSASS dumping, PPID spoofing |
| [Windows Attacks & Defense](./windows-attacks-and-defense/) | Active Directory attack paths and the detections that catch them |
| [Introduction to Malware Analysis](./introduction-to-malware-analysis/) | Static and dynamic analysis fundamentals |

## ▸ Network & web

| Module | Focus |
|---|---|
| [Intro to Network Traffic Analysis](./intro-to-network-traffic-analysis/) | Wireshark, tcpdump, protocol analysis, FTP/HTTP file extraction, live capture |
| [JavaScript Deobfuscation](./javascript-deobfuscation/) | Obfuscation types, UnPacker, Base64/Hex/ROT13 decoding, `curl` HTTP replication |

## ▸ Incident response

| Module | Focus |
|---|---|
| [Incident Handling Process](./incident-handling-process/) | Full IR lifecycle — preparation, detection, containment, eradication, recovery, lessons learned |
| [CDSA capstone incident report](./cdsa-capstone-incident-report/) | End-to-end incident report |

<br>

---

<div align="center">
<sub>Detection rules built from this material live in <a href="../detection-engineering/">detection-engineering</a>. Full investigation write-ups are in <a href="../investigations/">investigations</a>.</sub>
</div>
