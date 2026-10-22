# Rule: Volume Shadow Copy Deletion

**Platform:** Sigma — `process_creation` (Windows / Sysmon Event 1)
**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
**Severity:** Critical
**Signal strength:** ●●●● Near-zero baseline
**Rule ID:** `7b1a4c68-3d92-4e57-8f10-c6d4a297e5b3`

---

## What it detects

Shadow copies are Windows' built-in point-in-time backups. Deleting them is the last
action almost every ransomware family takes before or during encryption, because it is
what turns a recoverable incident into an unrecoverable one.

This is one of the highest-value detections a SOC can deploy, for three reasons that
rarely line up together:

- the baseline in a normal environment is **essentially zero**;
- the technique is **near-universal** across ransomware families;
- it fires inside a **narrow window where response can still limit the damage**.

Treat any hit as an active incident until proven otherwise. The cost of being wrong in
the other direction is the entire estate.

## The logic

The rule covers six separate ways to achieve the same end, because blocking only
`vssadmin delete shadows` moves an attacker one command to the left.

```yaml
detection:
  vssadmin_delete:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all: ['delete', 'shadows']
  vssadmin_resize:
    # Resizing storage to a tiny value silently discards existing shadow copies
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all: ['resize', 'shadowstorage']
  wmic_shadowcopy:
    Image|endswith: '\wmic.exe'
    CommandLine|contains|all: ['shadowcopy', 'delete']
  powershell_shadowcopy:
    Image|endswith: ['\powershell.exe', '\pwsh.exe']
    CommandLine|contains|all: ['Win32_ShadowCopy', 'Delete']
  wbadmin_delete:
    Image|endswith: '\wbadmin.exe'
    CommandLine|contains|all: ['delete', 'catalog']
  bcdedit_recovery:
    # Disabling recovery options commonly accompanies shadow copy deletion
    Image|endswith: '\bcdedit.exe'
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'bootstatuspolicy ignoreallfailures'
  condition: 1 of vssadmin_* or wmic_shadowcopy or powershell_shadowcopy
             or wbadmin_delete or bcdedit_recovery
```

Two of these are worth calling out. **`vssadmin resize shadowstorage`** to a tiny value
destroys existing copies without ever using the word *delete* — it is the quiet version
of the same action. **`bcdedit`** disabling recovery is not shadow-copy deletion at all,
but it travels with it so reliably that catching it in the same rule buys early warning.

## Fields to pull on a hit

`Image` · `CommandLine` · `ParentImage` · `ParentCommandLine` · `User` · `IntegrityLevel`

## False positives and tuning

| Source | Why it happens | What to do |
|---|---|---|
| Backup software | Some products rotate shadow copies as routine maintenance | Scope the exclusion to the backup **service account AND its expected parent process** |
| Disk cleanup utilities | May resize shadow storage | Rare — confirm rather than exclude |

The exclusion rule here is the important part: **never exclude on the command alone.**
`vssadmin delete shadows` from a backup service with the expected parent is maintenance;
the identical command from `winword.exe` is ransomware. Excluding the command deletes
the detection.

## Triage workflow

1. **Treat it as live.** Do not start by deciding whether it is a false positive. Start
   by establishing whether files are being encrypted right now.
2. **Identify the parent.** A scheduled backup task is a different world from an Office
   application, a browser child process, or a shell.
3. **Check for the rest of the pattern.** Mass file modification, ransom notes dropped
   in directories, `bcdedit` recovery changes, service stops, security tooling tampering.
4. **Scope laterally.** Ransomware operators run this across many hosts at once. Query
   the same rule estate-wide for the preceding hour before concluding it is isolated.

## Escalation criteria

| Finding | Action |
|---|---|
| Any hit not matching a documented backup job | **Escalate immediately — treat as active ransomware** |
| Hit on more than one host within the hour | **Escalate immediately — major incident** |
| Accompanied by `bcdedit` recovery changes | **Escalate immediately** |
| Known backup account, expected parent, scheduled window | Document and close |

## Testing it

On an isolated lab VM with a snapshot to roll back to, run
`vssadmin delete shadows /for=C: /oldest` from an elevated prompt and confirm the rule
fires on the Sysmon Event 1 record. Do not test this on anything you care about.

## Source

[`shadow-copy-deletion.yml`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/sigma-rules/shadow-copy-deletion.yml) — the rule as deployed.
