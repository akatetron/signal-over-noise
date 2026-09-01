# Detection: Privileged Group Membership Changes

**Platform:** Splunk (SPL)
**Data source:** Windows Security event logs (`WinEventLog:Security`)
**MITRE ATT&CK:** [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/), [T1078.002 — Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
**Severity:** High

---

## Why this detection exists

Adding an account to a privileged group is one of the most reliable persistence
mechanisms available to an attacker, and one of the quietest. It generates a single
event, it looks identical to legitimate administrative work, and once established it
survives password resets and endpoint reimaging.

The detection value comes not from the event itself but from **who made the change and
whether it was expected**. This search is therefore built to surface the change with
enough surrounding context that a Tier 1 analyst can make a call without pivoting
five times.

---

## Search

```spl
index=wineventlog sourcetype="WinEventLog:Security"
    EventCode IN (4728, 4732, 4756, 4729, 4733, 4757)
| eval action=case(
    EventCode IN (4728,4732,4756), "added",
    EventCode IN (4729,4733,4757), "removed")
| eval scope=case(
    EventCode IN (4728,4729), "Global group",
    EventCode IN (4732,4733), "Local group",
    EventCode IN (4756,4757), "Universal group")
| search TargetUserName IN ("Domain Admins","Enterprise Admins","Administrators",
    "Schema Admins","Account Operators","Backup Operators","Server Operators",
    "Group Policy Creator Owners","DnsAdmins")
| table _time, action, scope, TargetUserName, MemberName, SubjectUserName, ComputerName
| sort - _time
```

### Field meanings — the one people get backwards

| Field             | What it actually is                                      |
|-------------------|----------------------------------------------------------|
| `TargetUserName`  | The **group** that was modified                           |
| `MemberName`      | The **account added or removed** (often a raw SID)        |
| `SubjectUserName` | The account that **performed** the change                 |
| `ComputerName`    | Where the change was executed                             |

`MemberName` frequently arrives as a SID rather than a resolved name. Resolve it before
triaging — an unresolvable SID is itself suspicious, because it can indicate an account
deleted immediately after use to cover tracks.

---

## Higher-fidelity variant: changes outside the change window

Most legitimate privileged group changes happen during business hours, by a known set of
administrators. Encoding that assumption sharply reduces noise:

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4728, 4732, 4756)
| search TargetUserName IN ("Domain Admins","Enterprise Admins","Administrators")
| eval hour=strftime(_time,"%H"), day=strftime(_time,"%A")
| where (hour < 8 OR hour > 18) OR day IN ("Saturday","Sunday")
    OR NOT SubjectUserName IN ("admin.jsmith","admin.apatel","svc-idm-sync")
| table _time, day, hour, TargetUserName, MemberName, SubjectUserName, ComputerName
```

Replace the authorised-administrator list with the real one for the environment. This
turns a noisy informational search into a genuine alert.

---

## Self-elevation detection

The strongest single signal in this dataset is an account adding *itself* to a
privileged group — a pattern with essentially no legitimate explanation:

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4728, 4732, 4756)
| rex field=MemberName "CN=(?<member_cn>[^,]+)"
| eval member=coalesce(member_cn, MemberName)
| where lower(member)=lower(SubjectUserName)
| table _time, TargetUserName, member, SubjectUserName, ComputerName
```

---

## Triage workflow

1. **Is there a change ticket?** This is the single fastest disposition. No ticket for a
   Domain Admins change is an immediate escalation.
2. **Is `SubjectUserName` authorised to make this change?** A helpdesk account modifying
   Domain Admins is a privilege-escalation finding regardless of intent.
3. **Resolve `MemberName`.** New account, recently created account, or unresolvable SID
   all raise severity.
4. **Correlate backwards.** Pivot to Event 4720 (account created) — an account created
   and added to Domain Admins within minutes is a textbook persistence chain.
5. **Correlate forwards.** Check Event 4624 for the new member authenticating anywhere
   in the following hours.

## Escalation criteria

| Finding                                                    | Action             |
|-------------------------------------------------------------|--------------------|
| Change matches an approved ticket, made by an authorised admin | Close as benign  |
| Authorised admin, no ticket                                  | Consult IT Ops     |
| Any change to Domain Admins or Enterprise Admins             | **Escalate to T2** |
| Change made outside business hours                           | **Escalate to T2** |
| Account added itself                                         | **Escalate to T2** |
| Member account created within 24h of the change              | **Escalate to T2** |

---

## Tuning notes

Identity-management sync accounts (Entra ID Connect, Okta provisioning agents) legitimately
churn group membership continuously and will dominate results. Exclude them by name in
`SubjectUserName`, never by group — otherwise an attacker who compromises the sync account
inherits an allowlist.
