# Rule: Command Shell Spawned by a Non-Interactive System Utility

**Platform:** Sigma — `process_creation` (Windows / Sysmon Event 1)
**MITRE ATT&CK:** [T1134.004 — Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/) · [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
**Severity:** High
**Signal strength:** ●●●● Near-zero baseline
**Rule ID:** `3a7d5e21-9f48-4c62-b1a0-7d93e5c48f10`

---

## What it detects

An attacker who wants their payload to blend in can set a trusted process as the parent
of the process they spawn. The payload then appears in the process tree underneath
something unremarkable, and an analyst skimming parent names sees nothing odd.

This rule does not try to detect the spoofing call itself. It detects the thing the
spoofing produces: a **pairing that makes no sense**. The Windows Error Reporting
service has no reason to launch PowerShell. The print spooler has no reason to launch
`cmd.exe`. The desktop window manager has no reason to launch anything at all.

That is the useful property here. The attacker controls the command line completely, and
can rename the payload to whatever they like, but they cannot make a trusted parent a
*plausible* parent for an interactive shell.

## The logic

```yaml
detection:
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_parent:
    ParentImage|endswith:
      - '\WerFault.exe'        # Windows Error Reporting
      - '\wermgr.exe'
      - '\SearchIndexer.exe'
      - '\spoolsv.exe'         # print spooler
      - '\sihost.exe'
      - '\fontdrvhost.exe'
      - '\dwm.exe'             # desktop window manager
      - '\LogonUI.exe'
      - '\consent.exe'
  condition: selection_child and selection_parent
```

The parent list is deliberately short and specific. Every entry is a process that runs
constantly on a normal Windows host and never, in ordinary operation, spawns a shell.
Adding a parent that *sometimes* legitimately spawns a shell would trade the near-zero
baseline for noise, which is the whole value of the rule.

## Fields to pull on a hit

`ParentImage` · `ParentCommandLine` · `Image` · `CommandLine` · `User` · `CurrentDirectory`

`ParentCommandLine` matters as much as `ParentImage`. A real `WerFault.exe` is invoked
with a process ID and event handle; a spoofed parent reference often is not.

## False positives and tuning

| Source | Why it happens | What to do |
|---|---|---|
| Postmortem debugger | `WerFault` can legitimately invoke a debugger if `AeDebug` is configured in the registry | Check `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` before dismissing |
| Legacy print drivers | Some shell out from `spoolsv.exe` | Baseline per environment; scope the exclusion to the specific driver path |

Scope any exclusion to the **parent and the command together**, never to the command
alone. `powershell.exe` on its own is exactly what you are trying to catch.

## Triage workflow

1. **Read the full command line.** Encoded commands, `-enc`, `-w hidden`, download
   cradles and long base64 blobs move this straight to escalation.
2. **Check the parent's own lineage.** Walk up one more level. A `spoolsv.exe` that was
   itself spawned by something unusual is a different problem again.
3. **Check the user context and integrity level.** A shell running as `SYSTEM` from a
   spoofed parent is privilege escalation, not just evasion.
4. **Correlate on the host.** PPID spoofing is a defence-evasion step, not an objective.
   Look for what ran before it and what the shell did next.

## Escalation criteria

| Finding | Action |
|---|---|
| Encoded or obfuscated command line | **Escalate to T2** |
| Shell running as `SYSTEM` or with elevated integrity | **Escalate to T2** |
| Any subsequent network connection from the child process | **Escalate to T2** |
| Known debugger configured, command line matches it | Document and close |

## Testing it

Spawning a shell from a genuinely unusual parent is enough to fire this in a lab. The
cleanest safe test is to use a debugger configuration to have `WerFault` launch
`cmd.exe`, then confirm the Sysmon Event 1 record shows the expected parent/child pair.

## Source

[`ppid-spoofing-unusual-parent.yml`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/sigma-rules/ppid-spoofing-unusual-parent.yml) — the rule as deployed.
