# 🟣 HTB CDSA Capstone — Security Incident Report

**Type:** Original written incident report (capstone deliverable) · **Classification (as authored):** TLP:AMBER — Internal Use / Client Deliverable

> This is original analytical writing, not a guided module walkthrough — kept close to its original form rather than reformatted like the other folders in this repo. A phone number on the cover page has been redacted before publishing; everything else is unedited.

---

## What this document is

This is a full incident-response report written as a capstone exercise for HTB's CDSA (Certified Defensive Security Analyst) path, simulating a real client deliverable rather than a lab writeup. It investigates a single, multi-stage intrusion — from an initial malicious Word document on a workstation through to full domain controller compromise — entirely from log evidence: Elastic SIEM against Sysmon, Windows Security Auditing, Task Scheduler, and Service Control Manager events. The report follows a formal structure throughout: an executive summary with business impact and severity rating, a cyber kill chain mapping, and a section-by-section technical analysis that ties every finding to a specific data source, SIEM query, piece of evidence, and MITRE ATT&CK technique ID.

The attack chain it reconstructs, in order: a malicious Word document spawning PowerShell and reaching out to attacker infrastructure; Active Directory reconnaissance via SharpHound; local privilege escalation through a UAC bypass and scheduled-task persistence; Kerberoasting against a service account to obtain a crackable ticket; lateral movement to a second host via remote service execution; and finally Pass-the-Ticket authentication to the domain controller, malicious service installation, and access to LSASS memory via a disguised credential-dumping tool — a full chain ending in complete domain compromise with Golden Ticket potential.

## Why it's presented differently from the rest of this repo

Every other folder in this repository is a guided HTB Academy module, rebuilt here into a consistent walkthrough-plus-study-notes format. This one isn't a module — it's original report-writing work, already structured and complete on its own terms, so it's included close to its original form rather than reformatted into that template.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox CDSA Path*
