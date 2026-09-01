# Hunt: Password Spraying

**Platform:** Elastic / Kibana (KQL)
**Data source:** Windows Security event logs via Winlogbeat (`windows*` index)
**MITRE ATT&CK:** [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
**Severity:** High

---

## Hypothesis

Classic brute force hammers one account with many passwords — and lockout policy stops it
cold. Password spraying inverts the shape: **one password tried against many accounts**,
slowly enough that no individual account ever reaches its lockout threshold.

That inversion is why per-account alerting misses it entirely. An account with three
failures overnight looks like someone who forgot their password. Three hundred accounts
with three failures each, all within the same hour, all from one source, is an attack.

**The detection must therefore count distinct usernames per source, not failures per
account.** Getting that pivot right is the whole hunt.

---

## Query

### Step 1 — surface the candidate sources

```
event.code:4625 and not user.name:*$
```

Then in Kibana Lens:

| Setting | Value |
|---|---|
| Chart type | Table |
| Rows | `source.ip` (or `winlog.event_data.IpAddress`) |
| Metric 1 | **Unique count** of `user.name.keyword` |
| Metric 2 | Count of records |
| Sort | Unique count, descending |
| Time range | 1 hour, then repeat at 24 hours |

**Read it this way:** a source IP with a *high unique username count* but a *low
per-account failure count* is spraying. A source with a high failure count against **one**
username is ordinary brute force — different technique, different response.

### Step 2 — confirm the spray signature

```
event.code:4625
and source.ip:"<candidate_ip>"
and winlog.event_data.SubStatus:"0xC000006A"
```

`0xC000006A` means *the username exists but the password was wrong*. A source producing
this against dozens of valid usernames has a working list of your users — which is itself
worth investigating, since it implies prior enumeration or a leaked directory.

### Step 3 — the question that decides severity

```
event.code:4624
and source.ip:"<candidate_ip>"
```

**Did any attempt succeed?** A spray that failed everywhere is an attempted intrusion.
A spray with a single success is an *active* intrusion, and that account is now the
incident.

---

## Detection thresholds

Tune to environment size. Reasonable starting points:

| Window | Distinct users from one source | Verdict |
|---|---|---|
| 1 hour | 10+ | Investigate |
| 1 hour | 25+ | **Escalate** |
| 24 hours | 50+ | **Escalate** — low-and-slow spray |
| Any window | Any distinct-user spray **plus** a 4624 success | **Escalate immediately** |

Low-and-slow sprays deliberately stay under hourly thresholds. Running the same query at
a 24-hour window catches what the 1-hour view misses — worth scheduling both.

---

## Triage workflow

1. **Classify the source.** Internal IP suggests an already-compromised host spraying
   internally — that host is now also an incident. External suggests perimeter attack.
2. **Check the target list.** Sequential or alphabetical usernames indicate enumeration
   from a directory. A list weighted toward admin accounts indicates targeted
   reconnaissance and raises severity.
3. **Look for the success.** Step 3 above. This is the single most important question.
4. **If there was a success:** disable the account, kill active sessions, check Event 4672
   for privileges assigned, and pivot to what that account did next.
5. **Check for MFA.** A successful password does not mean successful access if MFA held.
   Confirm rather than assume.

## Escalation criteria

| Finding | Action |
|---|---|
| Under 10 distinct users, external, no success | Monitor, note the source |
| 25+ distinct users in one hour | **Escalate to T2** |
| Spraying originates from an internal host | **Escalate to T2** — that host is compromised |
| Admin or service accounts disproportionately targeted | **Escalate to T2** |
| Any successful 4624 from the spraying source | **Escalate immediately** |

---

## Tuning notes

The dominant false positive is a **misconfigured application or service** with stale
credentials retrying against many accounts — a mail client, a mobile device with an old
password, a broken SSO connector. These are distinguishable by consistency: they fail the
same way, on a fixed interval, forever. A human-driven or tooled spray shows bursts and
stops.

Do not exclude the source IP of an internal load balancer or VPN concentrator, even though
it will aggregate many users' failures and trigger this hunt. Excluding it blinds you to
every spray arriving through it. Instead pivot on `winlog.event_data.WorkstationName` or
the `X-Forwarded-For` equivalent to recover the true origin.
