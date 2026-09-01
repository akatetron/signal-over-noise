<div align="center">

# ◈ Detection Engineering

**Sigma · KQL · SPL · Suricata**

![Rules](https://img.shields.io/badge/Rules-10-9FEF00?style=flat-square&labelColor=141d2b)
![Techniques](https://img.shields.io/badge/ATT%26CK_Techniques-12-E4573D?style=flat-square&labelColor=141d2b)
![Platforms](https://img.shields.io/badge/Platforms-4-1F6FEB?style=flat-square&labelColor=141d2b)

<br>

> *A rule shipped without tuning guidance is a rule that gets disabled within a month.*

</div>

<br>

Detection logic written against the techniques studied across the HTB Academy CDSA path,
and directly from the [investigations](../investigations/) in this repository. Each rule
documents the reasoning behind it, its expected false positives, and how it should be
tuned.

<br>

---

## ▸ Sigma rules

Platform-agnostic detections written against Sysmon telemetry. Convertible to Splunk,
Elastic, Sentinel, or QRadar via `sigmac`.

| | Rule | Technique | Signal quality |
|:---:|---|---|---|
| 🔴 | [LSASS memory access](./sigma-rules/lsass-credential-access.yml) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) Credential dumping | ●●●○ Requires EDR allowlisting |
| 🔴 | [PPID spoofing](./sigma-rules/ppid-spoofing-unusual-parent.yml) | [T1134.004](https://attack.mitre.org/techniques/T1134/004/) Parent PID spoofing | ●●●● Near-zero baseline |
| 🔴 | [DLL search-order hijack](./sigma-rules/dll-hijack-nonstandard-path.yml) | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) Hijack execution flow | ●●○○ Installers create noise |
| 🔴 | [WMI lateral movement](./sigma-rules/wmi-lateral-movement.yml) | [T1047](https://attack.mitre.org/techniques/T1047/) WMI · [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | ●●●○ SCCM needs filtering |
| ⛔ | [Shadow copy deletion](./sigma-rules/shadow-copy-deletion.yml) | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit system recovery | ●●●● Near-zero baseline, ransomware |

## ▸ KQL hunts

Elastic and Kibana hunts against Windows Security logs. Each is structured as a
hypothesis, a query, a triage workflow, and explicit escalation criteria.

| | Hunt | Technique | Why it earns its place |
|:---:|---|---|---|
| 🟠 | [Disabled-account authentication](./kql-hunts/disabled-account-authentication.md) | [T1078](https://attack.mitre.org/techniques/T1078/) Valid accounts | `SubStatus 0xC0000072` isolates *disabled* from ordinary failures |
| 🟠 | [Service account interactive logon](./kql-hunts/service-account-interactive-logon.md) | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote services | Baseline is essentially zero — any hit is meaningful |
| 🟠 | [Password spraying](./kql-hunts/password-spray-detection.md) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password spraying | Counts distinct users per source — the pivot per-account alerting misses |

## ▸ Splunk SPL

| | Search | Technique | Notes |
|:---:|---|---|---|
| 🟡 | [Privileged group membership changes](./splunk-spl/privileged-group-membership-changes.md) | [T1098](https://attack.mitre.org/techniques/T1098/) Account manipulation | Includes a self-elevation variant with no benign explanation |

## ▸ Suricata rules

| | Ruleset | Coverage |
|:---:|---|---|
| 🔵 | [C2 beacon detection](./suricata-rules/c2-beacon-detection.rules) | Signature, anomaly (`dsize` + `detection_filter`), JA3 fingerprint, and WMI lateral movement |

<br>

---

## ▸ Design principles

<table>
<tr>
<td width="50%" valign="top">

**Detect behaviour, not artifacts**

A rule matching a filename or hash dies the moment the attacker renames the file. A rule matching *a signed binary loading a DLL from a user-writable directory* survives — it targets a constraint of the technique, not one implementation of it.

</td>
<td width="50%" valign="top">

**Every rule ships with its false positives**

A detection with no documented FP profile is unfinished work. The analyst receiving the alert at 3am needs to know what benign looks like before they can recognise malicious.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**Exclude by identity, not by category**

Excluding "all service accounts" hands an attacker a permanent allowlist. Excluding three named sync accounts does not.

</td>
<td width="50%" valign="top">

**Alert-only before blocking**

Every network rule here is `alert`, never `drop`. Inline blocking on an untuned rule creates an outage — and an outage caused by security tooling is how security tooling gets removed.

</td>
</tr>
</table>

<br>

---

<div align="center">
<sub>These rules were developed as lab exercises against HTB Academy environments and published as a demonstration of detection-engineering reasoning. They are starting points requiring environment-specific baselining — not drop-in production content.</sub>
</div>
