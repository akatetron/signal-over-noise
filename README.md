<div align="center">

# `signal › over › noise`

**Chayan Panchal** — SOC Analyst · Blue Team · Detection Engineering

<br>

[![HTB CDSA](https://img.shields.io/badge/HTB_CDSA_Path-Completed-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black&labelColor=141d2b)](https://academy.hackthebox.com)
[![Google Cybersecurity](https://img.shields.io/badge/Google_Cybersecurity-Certified-4285F4?style=for-the-badge&logo=google&logoColor=white&labelColor=141d2b)](https://www.coursera.org)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=141d2b)](https://www.linkedin.com/in/chayanpanchal)

<br>

![Detections](https://img.shields.io/badge/Detection_Rules-10-9FEF00?style=flat-square&labelColor=141d2b)
![Investigations](https://img.shields.io/badge/Investigations-2-9FEF00?style=flat-square&labelColor=141d2b)
![Modules](https://img.shields.io/badge/Lab_Write--ups-26-9FEF00?style=flat-square&labelColor=141d2b)
![ATT&CK](https://img.shields.io/badge/ATT%26CK_Techniques-12-E4573D?style=flat-square&labelColor=141d2b)

<br>

> *The job isn't seeing everything. It's knowing what matters.*

**Open to SOC Analyst roles — EU** *(sponsorship required)* **· Asia · Canada**

<sub>Currently based in St. John's, Newfoundland, Canada</sub>

</div>

<br>

---

<br>

## ◈ Start here

> Four links. If you only have five minutes, read the first one.

<table>
<tr>
<td width="50%" valign="top">

### ▸ [Multi-stage intrusion](./investigations/multi-stage-intrusion-windows-host/)
`DFIR` · `Sysmon` · `no EDR`

Reconstructing a five-stage attack chain from raw event logs with **no alert to start from**. Ends with the containment-scoping call — and why it wasn't a domain-wide reset.

📄 **[Formal incident report (PDF)](./investigations/multi-stage-intrusion-windows-host/IR-2026-0417-Multi-Stage-Intrusion-Incident-Report.pdf)**

</td>
<td width="50%" valign="top">

### ▸ [Seven SIEM findings](./investigations/siem-alert-triage-seven-findings/)
`Triage` · `KQL` · `escalation judgement`

First shift as Tier 1. Seven live findings, seven dispositions. **5 escalated, 2 consulted, 0 dismissed** — with the reasoning behind every call.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### ▸ [Detection engineering](./detection-engineering/)
`Sigma` · `KQL` · `SPL` · `Suricata`

Ten rules written from those investigations. Every one ships with its **false-positive profile and tuning notes**.

</td>
<td width="50%" valign="top">

### ▸ [HTB Academy — CDSA](./htb-academy/)
`11 modules` · `full walkthroughs`

SIEM, threat hunting, IDS/IPS, malware analysis, incident handling. Illustrated PDF walkthroughs throughout.

</td>
</tr>
</table>

<br>

---

<br>

## ◈ Detection engineering

<div align="center">

| | Rule | Platform | Technique | Signal |
|:---:|---|:---:|---|:---:|
| 🔴 | [LSASS memory access](./detection-engineering/sigma-rules/lsass-credential-access.yml) | `Sigma` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) Credential dumping | ●●●○ |
| 🔴 | [PPID spoofing](./detection-engineering/sigma-rules/ppid-spoofing-unusual-parent.yml) | `Sigma` | [T1134.004](https://attack.mitre.org/techniques/T1134/004/) Parent PID spoofing | ●●●● |
| 🔴 | [DLL search-order hijack](./detection-engineering/sigma-rules/dll-hijack-nonstandard-path.yml) | `Sigma` | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) Hijack execution flow | ●●○○ |
| 🔴 | [WMI lateral movement](./detection-engineering/sigma-rules/wmi-lateral-movement.yml) | `Sigma` | [T1047](https://attack.mitre.org/techniques/T1047/) · [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | ●●●○ |
| ⛔ | [Shadow copy deletion](./detection-engineering/sigma-rules/shadow-copy-deletion.yml) | `Sigma` | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit system recovery | ●●●● |
| 🟠 | [Disabled-account auth](./detection-engineering/kql-hunts/disabled-account-authentication.md) | `KQL` | [T1078](https://attack.mitre.org/techniques/T1078/) Valid accounts | ●●●● |
| 🟠 | [Service account RDP](./detection-engineering/kql-hunts/service-account-interactive-logon.md) | `KQL` | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote services | ●●●● |
| 🟠 | [Password spraying](./detection-engineering/kql-hunts/password-spray-detection.md) | `KQL` | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password spraying | ●●●● |
| 🟡 | [Privileged group changes](./detection-engineering/splunk-spl/privileged-group-membership-changes.md) | `SPL` | [T1098](https://attack.mitre.org/techniques/T1098/) Account manipulation | ●●●○ |
| 🔵 | [C2 beacon detection](./detection-engineering/suricata-rules/c2-beacon-detection.rules) | `Suricata` | [T1071](https://attack.mitre.org/techniques/T1071/) · [T1573](https://attack.mitre.org/techniques/T1573/) · [T1047](https://attack.mitre.org/techniques/T1047/) | ●●●○ |

</div>

<br>

### ATT&CK coverage

```
EXECUTION        PERSISTENCE      PRIV ESC         DEFENSE EVASION
T1059.001        T1574.001        T1574.001        T1134.004
T1047                                              T1574.001

CREDENTIAL ACC   DISCOVERY        LATERAL MVMT     COMMAND & CONTROL
T1003.001        T1033            T1021.001        T1071
T1078                             T1021.003        T1573
T1110.003                         T1047

ACCOUNT MANIP    IMPACT
T1098            T1490
```

<br>

---

<br>

## ◈ Lab write-ups

<details open>
<summary><b>HTB Academy — CDSA path</b> · 11 modules</summary>

<br>

| Module | Focus |
|---|---|
| [Security Monitoring & SIEM Fundamentals](./htb-academy/security-monitoring-siem-fundamentals/) | Elastic Stack, KQL, dashboard construction, alert triage |
| [Splunk for Security Analysts](./htb-academy/splunk-for-security-analysts/) | SPL, correlation searches, Splunk-based investigation |
| [Threat Hunting with Elastic](./htb-academy/threat-hunting-with-elastic/) | Hypothesis-driven hunting, EQL and KQL |
| [Windows Event Logs & Finding Evil](./htb-academy/windows-event-logs-finding-evil/) | Sysmon, DLL hijack, injection, LSASS dumping, PPID spoofing |
| [Windows Attacks & Defense](./htb-academy/windows-attacks-and-defense/) | Active Directory attack paths and their detections |
| [Working with IDS/IPS](./htb-academy/working-with-ids-ips/) | Suricata, Snort 3, Zeek, JA3 fingerprinting |
| [Intro to Network Traffic Analysis](./htb-academy/intro-to-network-traffic-analysis/) | Wireshark, tcpdump, protocol analysis, file extraction |
| [Introduction to Malware Analysis](./htb-academy/introduction-to-malware-analysis/) | Static and dynamic analysis fundamentals |
| [JavaScript Deobfuscation](./htb-academy/javascript-deobfuscation/) | Obfuscation types, decoding, HTTP replication |
| [Incident Handling Process](./htb-academy/incident-handling-process/) | Full IR lifecycle — preparation through lessons learned |
| [CDSA capstone incident report](./htb-academy/cdsa-capstone-incident-report/) | End-to-end incident report |

</details>

<details>
<summary><b>Google Cybersecurity Certificate</b> · 15 labs</summary>

<br>

| Lab | Focus |
|---|---|
| [Security Audits](./google-cybersecurity-certificate/security-audits/) | NIST CSF, compliance, Botium Toys case study |
| [Network Traffic Analysis](./google-cybersecurity-certificate/network-traffic-analysis/) | DNS, ICMP, UDP, log analysis |
| [Wireshark Labs](./google-cybersecurity-certificate/wireshark-labs/) | Packet analysis, display filters, TCP/HTTP |
| [tcpdump Labs](./google-cybersecurity-certificate/tcpdump-labs/) | Traffic capture, log interpretation |
| [Incident Response](./google-cybersecurity-certificate/incident-response/) | NIST IR lifecycle, journals, ransomware, DoS |
| [Linux File Permissions](./google-cybersecurity-certificate/linux-file-permissions/) | chmod, permission strings, least privilege |
| [SQL Security](./google-cybersecurity-certificate/sql-security/) | Security-focused queries, login log investigation |
| [Cryptography](./google-cybersecurity-certificate/cryptography/) | Hashing, SHA-256, Caesar cipher, OpenSSL |
| [Threat Modeling — PASTA](./google-cybersecurity-certificate/threat-modeling-pasta/) | 7-stage PASTA, attack trees, data flow diagrams |
| [Vulnerability Assessment](./google-cybersecurity-certificate/vulnerability-assessment/) | NIST SP 800-30, risk scoring, remediation |
| [Risk Management](./google-cybersecurity-certificate/risk-management/) | Risk register, asset inventory, scoring matrix |
| [Access Control](./google-cybersecurity-certificate/access-control/) | Least privilege, IAM, data leak analysis |
| [Network Hardening](./google-cybersecurity-certificate/network-hardening/) | MFA, firewalls, patch management, port filtering |
| [Social Engineering](./google-cybersecurity-certificate/social-engineering/) | USB baiting, phishing, physical security |
| [Brute Force Attacks](./google-cybersecurity-certificate/brute-force-attacks/) | Attack types, log analysis, prevention |

</details>

<details>
<summary><b>Handwritten study notes</b> · 6 PDF sets</summary>

<br>

Compiled notes across the full Google Cybersecurity Certificate.
→ [Browse notes](./handwritten-notes/)

</details>

<br>

---

<br>

## ◈ Toolchain

<div align="center">

![Elastic](https://img.shields.io/badge/Elastic-005571?style=flat-square&logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=flat-square&logo=kibana&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=flat-square)
![Snort](https://img.shields.io/badge/Snort_3-EF3B2D?style=flat-square)
![Zeek](https://img.shields.io/badge/Zeek-4B8BBE?style=flat-square)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-0078D6?style=flat-square&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-1F6FEB?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-E4573D?style=flat-square)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![SQL](https://img.shields.io/badge/SQL-4479A1?style=flat-square&logo=mysql&logoColor=white)

</div>

| Area | Detail |
|---|---|
| **SIEM** | Elastic Stack (Elasticsearch, Logstash, Kibana, Beats), Splunk, KQL, SPL |
| **Endpoint telemetry** | Sysmon, Windows Security event logs, PowerShell `Get-WinEvent` |
| **Network monitoring** | Suricata, Snort 3, Zeek, Wireshark, tcpdump, JA3 fingerprinting |
| **Detection engineering** | Sigma authoring, ATT&CK mapping, false-positive analysis, tuning |
| **Incident response** | NIST IR lifecycle, triage, escalation, containment scoping, reporting |
| **Frameworks** | MITRE ATT&CK, NIST CSF, NIST SP 800-30, PASTA |

<br>

---

<br>

## ◈ Scope of this work

I would rather state this plainly than have you wonder.

| | |
|---|---|
| **What this is** | Detection logic and investigation write-ups I produced myself, developed against HTB Academy lab environments and the Google Cybersecurity Certificate. The reasoning, tuning notes and escalation criteria are my own work. |
| **What this is not** | Production incident response. I have not yet held a SOC role, so none of this ran against live enterprise telemetry. The rules are documented starting points, not battle-tested content. |
| **Why publish it anyway** | Because Tier 1 hiring is about judgement — knowing why `SubStatus 0xC0000072` outranks an ordinary failed logon, or why a finding routes to IT Operations instead of Tier 2. That judgement is what these write-ups demonstrate, and it transfers. |

I can talk through any rule or decision in this repository in detail, including the false
positives I would expect and how I would tune around them.

<br>

---

<br>

## ◈ Certifications

<div align="center">

| Credential | Status |
|---|:---:|
| **HTB CDSA** — Certified Defensive Security Analyst | ✅ **Certified 22 Sep 2026** |
| ↳ credential `HTBCERT-88304FEA1D` · 11-module path + practical exam | *verifiable* |
| **Google Cybersecurity Professional Certificate** · `GBEGPUJOSIJ7` | ✅ Certified |
| **IELTS English** (B2) | ✅ Certified |
| Blue Team Level 1 (BTL1) | 📅 Planned |

</div>

<br>

---

<br>

<div align="center">

## ◈ Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Chayan_Panchal-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=141d2b)](https://www.linkedin.com/in/chayanpanchal)
[![HackTheBox](https://img.shields.io/badge/HackTheBox-@DarkHexReaper-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black&labelColor=141d2b)](https://academy.hackthebox.com/achievement/badge/de728e19-b659-11f1-82d1-bea50ffe6cb4)

**St. John's, Newfoundland, Canada**
Open to SOC Analyst · Blue Team roles in the **EU** *(sponsorship required)*, **Asia**, and **Canada**

<br>

<sub>All work is my own hands-on lab practice. Detection rules were developed against lab environments and are documented as reasoning demonstrations — they require environment-specific baselining before production use. Graded HTB Academy answers are masked per HTB's publication guidance.</sub>

</div>
