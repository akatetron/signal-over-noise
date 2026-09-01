# Hunt: Authentication Attempts Against Disabled Accounts

**Platform:** Elastic / Kibana (KQL)
**Data source:** Windows Security event logs via Winlogbeat (`windows*` index)
**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Severity:** High

---

## Hypothesis

When an employee offboards, their account is disabled but the credentials themselves
do not change. If someone attempts to authenticate against a disabled account, one of
three things is true:

1. A former employee still holds working credentials and is trying to use them.
2. An attacker harvested credentials before the account was disabled.
3. A forgotten service or scheduled task is still using the account.

All three warrant investigation. The third is the most common and the easiest to
confirm — which makes this a high-value, low-noise hunt.

The key insight is that Windows Event 4625 (failed logon) carries a `SubStatus` code
explaining *why* authentication failed. Most failures are noise (wrong password,
expired password). `0xC0000072` specifically means **the account is disabled** — the
credentials themselves may well have been correct.

---

## Query

```
event.code:4625 and winlog.event_data.SubStatus:"0xC0000072"
```

### Broadened — all high-signal failure reasons, excluding noise

```
event.code:4625
and winlog.event_data.SubStatus:("0xC0000072" or "0xC0000064" or "0xC0000234")
and not user.name:*$
```

| SubStatus    | Meaning                        | Why it matters                                    |
|--------------|--------------------------------|---------------------------------------------------|
| `0xC0000072` | Account is disabled            | Credentials may be valid; account shouldn't work  |
| `0xC0000064` | Username does not exist        | Username enumeration / spraying                   |
| `0xC0000234` | Account locked out             | Result of a brute-force attempt                   |
| `0xC000006A` | Wrong password                 | Usually noise on its own — correlate on volume    |
| `0xC0000193` | Account expired                | Usually benign                                    |
| `0xC0000071` | Password expired               | Usually benign                                    |

The `not user.name:*$` clause drops machine accounts, which end in `$` and generate
constant authentication noise that will otherwise bury the signal.

---

## Triage workflow

1. **Identify the account.** Was it deliberately disabled? Check the offboarding record
   and Event 4725 (account disabled) for who disabled it and when.
2. **Identify the source.** Pivot on `source.ip` and `winlog.event_data.WorkstationName`.
   An attempt from the ex-employee's old workstation reads very differently from one
   originating outside the corporate range.
3. **Check the volume and cadence.** A single attempt at 09:00 on a Monday is likely a
   forgotten mapped drive or scheduled task. Hundreds of attempts across many accounts
   is credential stuffing.
4. **Check for success.** Pivot to `event.code:4624` for the same `source.ip` in the
   surrounding window. If the actor pivoted to a *different* account and succeeded, the
   disabled-account failure was the first visible symptom of a live intrusion.

## Escalation criteria

| Finding                                                       | Action              |
|---------------------------------------------------------------|---------------------|
| Single attempt, internal host, known offboarded user           | Consult IT Ops      |
| Repeated attempts across multiple disabled accounts            | **Escalate to T2**  |
| Attempt from external or unrecognised source IP                | **Escalate to T2**  |
| Any subsequent 4624 success from the same source               | **Escalate to T2**  |

---

## Tuning notes

Service accounts are the dominant false positive. A service account that fails
authentication is usually a configuration problem, not an attack — but it is still
worth surfacing, because a service account that *shouldn't* be authenticating at all
is a genuine finding. Rather than excluding them, split them into their own dashboard
panel so they are triaged separately with different urgency.
