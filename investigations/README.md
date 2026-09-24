<div align="center">

# ◈ Investigations

**Full analytical write-ups — start to disposition**

![Investigations](https://img.shields.io/badge/Investigations-2-9FEF00?style=flat-square&labelColor=141d2b)
![Techniques](https://img.shields.io/badge/ATT%26CK-12_techniques-E4573D?style=flat-square&labelColor=141d2b)

<br>

> *These are the write-ups to read first. Everything else in this repository is supporting evidence.*

</div>

<br>

---

<br>

<table>
<tr>
<td width="50%" valign="top">

### ▸ [Multi-stage intrusion on a Windows host](./multi-stage-intrusion-windows-host/)

`DFIR` `Sysmon` `no EDR` `T1574.001` `T1055` `T1003.001` `T1134.004`

**The scenario.** No alert fired. No EDR pointing at a suspicious process. Just raw event logs on a host believed to be compromised — and the first problem was deciding where to look at all.

**The outcome.** Five-stage attack chain fully reconstructed: DLL hijack → CLR injection → `CreateRemoteThread` → LSASS dump → PPID-spoofed discovery.

**The call that matters.** Credentials were stolen but *not yet used*. That negative finding is the difference between isolating one host and assuming domain compromise.

📄 **[Read the formal incident report (PDF)](./multi-stage-intrusion-windows-host/IR-2026-0417-Multi-Stage-Intrusion-Incident-Report.pdf)** — written as a client deliverable.

</td>
<td width="50%" valign="top">

### ▸ [Triaging seven SIEM findings](./siem-alert-triage-seven-findings/)

`Triage` `KQL` `escalation judgement` `T1078` `T1021.001` `T1098`

**The scenario.** First shift as Tier 1 in a defined environment — cloud-only, four admins, PAW policy, `svc-` prefixed service accounts, root SSH disabled.

**The outcome.** Seven findings, seven dispositions: **5 escalated, 2 consulted, 0 dismissed.**

**The lesson.** Half the dispositions were decided by a documented policy rather than log analysis. Reading the environment's controls is analyst work, not paperwork.

</td>
</tr>
</table>

<br>

---

<br>

## ▸ How these are structured

Every write-up follows the same shape, because that shape is what an incident report has
to contain.

| | Section | What it covers |
|:---:|---|---|
| `1` | **Starting position** | What was known, what tooling was available, and critically what was *not* |
| `2` | **Approach** | Why I looked where I looked first, rather than reading chronologically |
| `3` | **Findings** | Each stage with the query that surfaced it and the reasoning that interpreted it |
| `4` | **Disposition** | The call made, and the criteria behind it |
| `5` | **What I'd do differently** | Telemetry gaps, earlier detections, containment scoping |

<br>

> **Negative findings are documented alongside positive ones.**
> Establishing that stolen credentials were *not* subsequently used is worth more than
> another indicator — it is what scopes the entire response.

<br>

---

<div align="center">
<sub>Detection rules written from these investigations live in <a href="../detection-engineering/">detection-engineering</a>.</sub>
</div>
