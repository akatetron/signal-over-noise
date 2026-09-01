# 🔑 Access Control

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Framework:** NIST SP 800-53 (AC-6 — Least Privilege)

## What this lab was about

Access control is the practice of enforcing least privilege — making sure users can only reach the resources their role actually requires. This folder covers two worksheets built around that idea: an incident investigation into a former contractor who kept admin-level payroll access years after his contract ended, and an analysis of a data leak caused by an internal folder that was shared too broadly and never locked back down. Both exercises trace the finding back to NIST SP 800-53's AC-6 control and turn it into concrete recommendations.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full walkthrough of both incidents with the NIST AC-6 control breakdown. Quick reference on the last page. |
| `source-files/Access control worksheet_.docx` | Original lab worksheet (given) |
| `source-files/Activity _ Data leak worksheet.docx` | Original lab worksheet (given) |
| `source-files/Accounting exercise.xlsx` | Original lab spreadsheet (given) |

## Complete walkthrough

### Incident 1 — unauthorized payroll access

An authorization review flagged an account — Robert Taylor Jr., a former contractor whose engagement ended in 2019 — that still had admin-level access and used it to reach payroll systems in 2023, four years later. No account expiration policy had ever kicked in to catch it. The recommendation set follows directly from the failure: auto-expire accounts after a period of inactivity or contract end, scope contractor access tightly from the start, and require MFA so a still-valid-but-stale credential isn't enough on its own.

### Incident 2 — data leak from overpermissioned sharing

A sales manager shared an internal folder — containing an unannounced product, customer analytics, and promotional material — with their team during a meeting, and never revoked access afterward. Later, a sales rep meant to send a public promotional link to a business partner but pasted the internal folder link by mistake. The partner, assuming it was the public material, posted it on social media. Mapped against the NIST Cybersecurity Framework, this lands under Protect → PR.DS (Data Security) → PR.DS-5 (protections against data leaks), which points back to the same AC-6 least-privilege control: if the internal folder's access had been correctly scoped and time-limited, the human mistake downstream would have exposed nothing.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
