# Hunt: Service Accounts Performing Interactive or RDP Logons

**Platform:** Elastic / Kibana (KQL)
**Data source:** Windows Security event logs via Winlogbeat (`windows*` index)
**MITRE ATT&CK:** [T1078.002 — Domain Accounts](https://attack.mitre.org/techniques/T1078/002/), [T1021.001 — RDP](https://attack.mitre.org/techniques/T1021/001/)
**Severity:** High

---

## Hypothesis

Service accounts exist to run processes non-interactively. They typically have elevated
privileges, passwords that rotate rarely or never, and — critically — no human who would
notice their misuse. That combination makes them a favourite for lateral movement.

A service account should generate logon type 5 (Service) or 4 (Batch). It should almost
never generate logon type 2 (Interactive), 10 (RemoteInteractive / RDP), or 7 (Unlock).
When it does, either the account is being misused, or an administrator is taking a
shortcut that needs to be corrected. Both are findings.

This hunt is high-value precisely because the baseline is *nearly zero*. Unlike failed
logons, there is no ambiguity to wade through.

---

## Query

```
event.code:4624
and winlog.event_data.LogonType:(2 or 7 or 10 or 11)
and user.name:svc-*
```

### Environment-agnostic variant

Naming conventions vary. If service accounts are not consistently prefixed, invert the
logic and hunt on the privilege instead:

```
event.code:4624
and winlog.event_data.LogonType:(2 or 10)
and winlog.event_data.TargetUserName:(*svc* or *service* or *_sa or sql* or backup*)
and not winlog.event_data.TargetUserName:*$
```

### Logon type reference

| Type | Name              | Expected for a service account? |
|------|-------------------|---------------------------------|
| 2    | Interactive       | No — console logon              |
| 3    | Network           | Yes — file share / SMB access   |
| 4    | Batch             | Yes — scheduled task            |
| 5    | Service           | Yes — this is the normal case   |
| 7    | Unlock            | No                              |
| 10   | RemoteInteractive | No — this is RDP                |
| 11   | CachedInteractive | No                              |

---

## Triage workflow

1. **Confirm the account is genuinely a service account.** Check the description field
   in AD and whether it is a member of any service-account OU or group.
2. **Establish where it logged on from.** `source.ip` plus `winlog.event_data.WorkstationName`.
   A logon originating from an admin's workstation suggests a human using shared
   credentials; one from an unexpected server suggests lateral movement.
3. **Establish where it logged on *to*.** A SQL service account RDPing into a PKI server
   or domain controller has no plausible legitimate explanation.
4. **Correlate with privilege escalation.** Pivot to Event 4672 (special privileges
   assigned) for the same logon ID, and Event 4732 (added to a security group) in the
   surrounding window.
5. **Check what ran afterwards.** Pivot to Sysmon Event 1 filtered on the same user —
   an interactive service-account session followed by `cmd.exe`, `powershell.exe`, or
   discovery commands (`whoami`, `net group`, `nltest`) escalates immediately.

## Escalation criteria

| Finding                                                          | Action             |
|------------------------------------------------------------------|--------------------|
| Interactive logon on the server the account legitimately runs on  | Consult IT Ops     |
| RDP to any host, from any source                                  | **Escalate to T2** |
| Logon to a tier-0 asset (DC, PKI, backup server)                  | **Escalate to T2** |
| Followed by 4672, group changes, or discovery commands            | **Escalate to T2** |

---

## Tuning notes

The most common legitimate hit is an administrator troubleshooting a broken service by
logging in as the service account directly. This is poor practice rather than an attack,
but it should not be silently allowlisted — the correct response is to route it to IT
Operations so the behaviour is corrected, otherwise it permanently erodes the value of
this detection by training analysts to dismiss it.

If a specific maintenance window generates predictable noise, scope the exclusion to
that time range and those hosts rather than excluding the account outright.
