# Rule: LSASS Memory Access by a Non-System Process

**Platform:** Sigma — `process_access` (Sysmon Event 10)
**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
**Severity:** High
**Signal strength:** ●●●○ Requires EDR and AV allowlisting
**Rule ID:** `8f2c1d94-6b3e-4a17-9c85-2e4f7a1b0d33`

---

## What it detects

`lsass.exe` holds credentials, hashes and Kerberos tickets in memory. Any process that
opens a handle to it with read rights is asking for exactly the thing an attacker wants,
which makes Sysmon Event 10 (`ProcessAccess`) one of the highest-signal events Windows
can produce.

The rule matches on the **access mask**, not on tool names. Matching `mimikatz.exe`
catches nobody — the file gets renamed. Matching the specific `GrantedAccess` values that
a memory read requires catches the technique regardless of what the binary is called,
including `procdump`, `comsvcs.dll MiniDump`, and anything hand-rolled.

## The logic

```yaml
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'   # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION — classic minidump
      - '0x1410'   # adds PROCESS_QUERY_INFORMATION
      - '0x1438'
      - '0x143a'
      - '0x1f0fff' # PROCESS_ALL_ACCESS
  filter_system:
    SourceImage|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
    SourceImage|endswith:
      - '\wininit.exe'
      - '\csrss.exe'
      - '\services.exe'
      - '\svchost.exe'
      - '\lsm.exe'
      - '\MsMpEng.exe'      # Defender
  condition: selection and not filter_system
```

Note that `filter_system` requires **both** a System32 path and a known binary name. A
file called `svchost.exe` sitting in a user's Temp directory does not match the filter,
which is the point — binary name alone is attacker-controlled.

## Access masks, decoded

| Mask | Rights | Why it appears |
|---|---|---|
| `0x1010` | `PROCESS_VM_READ` + `PROCESS_QUERY_LIMITED_INFORMATION` | The classic minidump combination |
| `0x1410` | adds `PROCESS_QUERY_INFORMATION` | Common variant |
| `0x1438` / `0x143a` | read + query + additional rights | Seen from several dumping tools |
| `0x1f0fff` | `PROCESS_ALL_ACCESS` | Blunt; usually an unsophisticated tool |

## Fields to pull on a hit

`SourceImage` · `SourceProcessId` · `TargetImage` · `GrantedAccess` · `CallTrace` · `User`

`CallTrace` is the field that settles most cases. A legitimate security product's call
trace resolves through its own signed modules; a dumping tool's frequently shows
`UNKNOWN` frames or resolves through `dbghelp.dll` / `dbgcore.dll`.

## False positives and tuning

| Source | Why it happens | What to do |
|---|---|---|
| EDR and AV agents | They legitimately inspect LSASS | Baseline your security stack's binaries and add them to `filter_system` |
| Backup and performance monitoring | Some query LSASS metadata | Add by full path, confirm the vendor signature |

Tune by **adding trusted sources to the filter**, never by widening the `GrantedAccess`
list. The access mask is the detection; loosening it removes the rule's reason to exist.

## Triage workflow

1. **Resolve the source process.** Full path, signature status, parent. An unsigned
   binary in a user-writable directory reading LSASS is an incident.
2. **Read `CallTrace`.** `dbghelp.dll` or `dbgcore.dll` frames indicate a minidump call.
   `UNKNOWN` frames indicate unbacked memory — commonly injected code.
3. **Check what happened next.** A dump has to go somewhere. Look for file writes near
   the event, and for outbound transfers.
4. **Assume credentials are compromised** until you can show the dump failed. Scope which
   accounts had sessions on that host.

## Escalation criteria

| Finding | Action |
|---|---|
| Unsigned or unknown source process | **Escalate to T2** |
| `CallTrace` containing `UNKNOWN` frames | **Escalate to T2** |
| Any file write of a `.dmp` near the event | **Escalate to T2 — assume credential theft** |
| Known EDR binary, correct path and signature | Add to filter, close |

## Testing it

In a lab, `procdump -ma lsass.exe out.dmp` from an elevated prompt produces a clean
Event 10 with `GrantedAccess: 0x1fffff` or similar. Compare the `CallTrace` with that of
your own EDR agent's routine access to see the difference the field makes.

## Source

[`lsass-credential-access.yml`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/sigma-rules/lsass-credential-access.yml) — the rule as deployed.
