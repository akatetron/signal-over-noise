# Investigation: Triaging Seven SIEM Findings

**Environment:** HTB Academy — fictional org "Eagle", Elastic/Kibana SIEM
**Role simulated:** Tier 1 SOC analyst, first shift
**Task:** Review seven dashboard findings and disposition each one
**Outcome:** 7/7 correctly dispositioned

---

## Why this exercise matters more than it looks

Building a Kibana dashboard is a mechanical skill. Deciding what a finding *means* is
the job. The same event — a service account logging on — is routine in one environment
and a critical incident in another. Tier 1 gets hired for that judgement, and it is the
thing that does not transfer from a certificate.

Every disposition below resolves to one of three outcomes:

| Disposition | Meaning |
|---|---|
| **Nothing suspicious** | Fully explained by expected behaviour |
| **Consult IT Operations** | Plausibly legitimate, needs context before a call |
| **Escalate to Tier 2/3** | Clear indicator of compromise, or high-risk with no benign explanation |

The middle option is the one new analysts skip, and skipping it is how you either flood
Tier 2 with noise or close a real incident as benign.

---

## The environment — context is the whole job

Disposition is impossible without knowing what normal looks like. Eagle's documented
environment:

- **Cloud-only.** No on-premises infrastructure.
- **Four IT administrators.** A known, finite set of people who should be doing admin work.
- **Privileged Access Workstation (PAW) policy.** Admin accounts authenticate only from
  designated hardened workstations.
- **Service accounts prefixed `svc-`.** They run local processes. They do not roam.
- **Root SSH login disabled by policy.**

Each of these is a tripwire. A finding that violates a documented policy needs no further
analysis to justify escalation — the policy already encodes the organisation's judgement.

---

## The seven findings

### 1 — Failed logons for `sql-svc1`

**Query:** `event.code:4625` excluding machine accounts.

A service account generating failed authentications. Service accounts authenticate with
stored credentials — they either work or they are misconfigured. They should not fail
intermittently.

**Not automatically an attack.** The most common cause is a password rotation that missed
one system. But it can equally be a password-spray attempt against a known account name.
Distinguishing them requires knowing whether a rotation happened, and that is IT
Operations' knowledge, not mine.

**Disposition: Consult IT Operations.**

---

### 2 — Failed logons against a disabled account (`anni`)

**Query:** `event.code:4625 and winlog.event_data.SubStatus:"0xC0000072"`

The `SubStatus` code is what makes this finding sharp. `0xC0000072` does not mean the
password was wrong — it means the password may well have been *right*, and the logon was
refused because the account is disabled.

Someone possesses credentials for an account that was deliberately switched off. There is
no benign version of that with an unexplained source.

**Disposition: Escalate.**

This finding became the [disabled-account KQL hunt](../../detection-engineering/kql-hunts/disabled-account-authentication.md).

---

### 3 — `svc-sql1` RDP into the PKI server

**Query:** `event.code:4624 and winlog.logon.type:RemoteInteractive and user.name:svc-*`

Three independent violations stacked in one event:

1. A service account performed an **interactive** logon.
2. It did so via **RDP** — service accounts have no interactive session requirement.
3. The destination was the **PKI server** — a tier-0 asset. Compromise of the certificate
   authority means the attacker can mint trusted certificates at will.

Source IP `192.168.28.130`. Any one of these justifies escalation; together they are a
lateral-movement pattern.

**Disposition: Escalate.**

This finding became the [service-account logon hunt](../../detection-engineering/kql-hunts/service-account-interactive-logon.md).

---

### 4 — Unrecognised SID added to Administrators

**Query:** `event.code:(4732 or 4733)` over an absolute time range.

An account was added to the local Administrators group on 2023-03-05, and the SID did not
resolve to a recognised user.

This is genuinely ambiguous, and resisting the urge to escalate immediately is the correct
instinct. Administrators add accounts to admin groups — that is the job. An unresolvable
SID often means a deleted account or a cross-domain reference, both of which have mundane
explanations. But it can also mean an account created for persistence and deleted to cover
the trail.

The deciding factor is whether a change ticket exists. That is IT Operations' record.

**Disposition: Consult IT Operations.**

This finding became the [privileged group membership SPL search](../../detection-engineering/splunk-spl/privileged-group-membership-changes.md).

---

### 5–6 — Admin logons outside the PAW policy

Administrator accounts authenticating from workstations that are not designated PAWs.

The organisation has already made this decision. A PAW policy exists precisely because
admin credentials entered on a general-purpose workstation are exposed to whatever that
workstation is running — a keylogger, an infostealer, a malicious browser extension.

There is no analysis to perform. The behaviour violates a documented control.

**Disposition: Escalate.**

---

### 7 — Root SSH login

Root SSH is disabled by policy. A successful root SSH login therefore means either the
control was bypassed, or it was never correctly applied.

Both are serious. A successful authentication that policy says is impossible is the
strongest single finding in the set, because it indicates the environment is not in the
state it is documented to be in — which undermines the assumptions behind every other
disposition made here.

**Disposition: Escalate.**

---

## Results

| # | Finding | Disposition |
|---|---|---|
| 1 | Service account failed logons | Consult IT Ops |
| 2 | Disabled account authentication | **Escalate** |
| 3 | Service account RDP to PKI | **Escalate** |
| 4 | Unrecognised SID → Administrators | Consult IT Ops |
| 5 | Admin logon outside PAW | **Escalate** |
| 6 | Admin logon outside PAW | **Escalate** |
| 7 | Root SSH login | **Escalate** |

**5 escalations, 2 consultations, 0 dismissed.**

---

## What I took from this

**Policy documents are detection content.** Half of these dispositions were decided by a
documented control rather than by log analysis. "Root SSH is disabled" converts a
successful root SSH login from an ambiguous event into an unambiguous one. Reading the
environment's policies is analyst work, not paperwork.

**`SubStatus` is where the signal lives.** Alerting on Event 4625 alone generates noise
nobody reads. Alerting on `4625 + 0xC0000072` generates findings people act on. The
difference between a useless detection and a good one is often one field.

**"Consult IT Operations" is a real answer.** Findings 1 and 4 were genuinely ambiguous.
Escalating them would have burned Tier 2 time; closing them as benign would have risked
missing a real intrusion. Routing them to the team holding the missing context is the
correct call, and being willing to make it is what stops an analyst from becoming either
a bottleneck or a rubber stamp.

**Tier-0 assets change the maths.** Finding 3 would still be a finding if the destination
were a print server. Because it was the PKI server, it became an immediate escalation.
Knowing which assets are tier-0 has to happen before the alert arrives.

---

## Related material

- [Security Monitoring & SIEM Fundamentals](../../htb-academy/security-monitoring-siem-fundamentals/) — the underlying module
- [Detection engineering](../../detection-engineering/) — rules built from these findings
