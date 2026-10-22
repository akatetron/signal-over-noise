# Rule: WMI Remote Process Execution

**Platform:** Sigma — `process_creation` (Windows / Sysmon Event 1)
**MITRE ATT&CK:** [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) · [T1021.003 — Remote Services: DCOM](https://attack.mitre.org/techniques/T1021/003/)
**Severity:** High
**Signal strength:** ●●●○ SCCM needs filtering
**Rule ID:** `5d9e2f71-4c83-4b06-a2f7-91e6c3b58d24`

---

## What it detects

Remote WMI execution — `wmiexec`, `Invoke-WmiMethod`, `wmic /node:` — is a favoured
lateral movement channel for three reasons: WMI is built into Windows, it runs over an
RPC channel that is usually already permitted, and it writes nothing to disk on the
target.

When a command arrives over WMI, the WMI Provider Host (`WmiPrvSE.exe`) is what spawns
it. That parent relationship is a **structural property of how WMI executes remote
commands** — it is not something the attacker chooses. The command line, by contrast, is
entirely attacker-controlled.

So the rule keys on the parent, and uses the command line only to separate the
interesting children from the vast amount of legitimate WMI query traffic.

## The logic

```yaml
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  suspicious_children:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
  discovery_commands:
    CommandLine|contains:
      - 'whoami'
      - 'net group'
      - 'net localgroup'
      - 'nltest'
      - 'systeminfo'
      - 'qwinsta'
      - 'tasklist'
  filter_sccm:
    ParentCommandLine|contains: ['CcmExec', 'SMS Agent']
  condition: selection and (suspicious_children or discovery_commands) and not filter_sccm
```

The `discovery_commands` branch exists because the first thing an operator does after
landing on a new host is work out where they are. Catching the orientation commands
often gets you the intrusion a step before anything is executed.

## Fields to pull on a hit

`ParentImage` · `Image` · `CommandLine` · `User` · `LogonId`

`LogonId` is the one to pivot on. It ties this execution to the logon session, which
tells you which account was used for the lateral movement and where it came from.

## False positives and tuning

| Source | Why it happens | What to do |
|---|---|---|
| SCCM / MECM, Intune | Use WMI heavily for inventory and software deployment | Filter on the **specific management service account**, not the rule |
| Monitoring agents (Nagios, PRTG, SolarWinds) | Query hosts over WMI | Mostly excluded already — they do not normally spawn shells |
| Admin troubleshooting | Genuine remote administration | Correlate with a change ticket |

This rule needs the most environment-specific tuning of the five Sigma rules here, which
is why its signal strength is three bars rather than four. In an estate with heavy SCCM
use, start it in audit mode and build the service-account filter before alerting.

## Triage workflow

1. **Establish the source.** Pivot on `LogonId` to the 4624 logon event, then to the
   source IP. Remote WMI from a workstation to a workstation is far more suspicious than
   from a known management server.
2. **Is the account meant to do this?** A service account for an application has no
   business executing WMI commands against other hosts.
3. **Read the command.** Discovery commands suggest early-stage orientation. Download
   cradles and encoded commands suggest payload delivery.
4. **Check the fan-out.** One host is lateral movement. Ten hosts in five minutes is an
   automated spread.

## Escalation criteria

| Finding | Action |
|---|---|
| Source is not a known management server | **Escalate to T2** |
| Encoded or obfuscated command line | **Escalate to T2** |
| Same source reaching multiple destinations | **Escalate to T2 — likely automated** |
| Known SCCM service account and parent | Add to filter, close |

## Testing it

From an admin context in a lab domain, `wmic /node:TARGET process call create "cmd.exe
/c whoami"` produces the parent/child relationship this rule looks for. Check that the
Sysmon record on the **target** shows `WmiPrvSE.exe` as parent.

## Source

[`wmi-lateral-movement.yml`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/sigma-rules/wmi-lateral-movement.yml) — the rule as deployed.
