# Investigation: Multi-Stage Intrusion on a Windows Host

**Environment:** HTB Academy lab — single compromised Windows endpoint
**Telemetry available:** Sysmon, Windows Security event log
**Tooling:** `Get-WinEvent`, Event Viewer — no EDR, no alert to start from
**Outcome:** Full attack chain reconstructed across five stages
**MITRE coverage:** T1574.001 · T1055 · T1003.001 · T1134.004

---

## The problem

No alert fired. There was no EDR console pointing at a suspicious process, no SIEM
correlation rule surfacing a chain. The starting position was raw event logs on a host
that was believed to be compromised, and the task was to establish whether that was true
and, if so, what had happened.

This is the harder version of the job. Triaging an alert means something has already told
you where to look. Here the first problem was deciding where to look at all.

---

## Approach

Sysmon produces a large volume of events, most of them benign. Rather than reading
chronologically, I worked backwards from the event types that carry the highest signal
per volume:

| Sysmon event | What it captures | Why start here |
|---|---|---|
| **7** — ImageLoaded | Every DLL load | Hijacks surface as path anomalies |
| **8** — CreateRemoteThread | Cross-process thread creation | Almost always injection |
| **10** — ProcessAccess | Handle opened to another process | Credential dumping is visible here |
| **1** — ProcessCreate | Process creation with parent | Parent/child anomalies |

Event 8 in particular has an extremely low legitimate baseline. Filtering on it first is
a cheap way to find a foothold in an unfamiliar dataset.

---

## Stage 1 — DLL search-order hijack

**Sysmon Event 7 (ImageLoaded).**

A trusted Windows executable was loading a DLL from `C:\ProgramData` rather than
`System32`. Three things made this unambiguous:

- **Wrong directory.** The legitimate DLL lives in `System32`. `C:\ProgramData` is
  user-writable, which is precisely why it was chosen.
- **Placeholder version metadata.** `FileVersion 0.0.0.0` — Microsoft-shipped binaries
  always carry a real version string.
- **No company name.** The field was blank.

Any one of these alone might be explained away. Together they describe a hand-built
payload placed where Windows' DLL search order would find it before the real one.

**Query used:**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 -and $_.Message -match "ProgramData" } |
    Select-Object TimeCreated, Message
```

This established both the initial access vector and the staging directory — which
mattered later.

---

## Stage 2 — Unmanaged PowerShell via CLR injection

**Sysmon Event 7 again, different question.**

`clr.dll` is the .NET Common Language Runtime. It loads whenever managed code runs. The
hunt was for a process with no legitimate reason to execute .NET code that had loaded it
anyway.

Finding one indicates **unmanaged PowerShell** — shellcode that hosts the CLR inside an
arbitrary process to execute PowerShell-equivalent code *without ever launching
`powershell.exe`*. This defeats every detection built around monitoring that process
name, which is a large proportion of naive PowerShell detection.

The lesson that transfers: detections keyed to a process *name* are brittle. The same
capability reached through a different host process walks straight past them. Detections
keyed to the *capability* — an unexpected process loading the runtime it needs — hold up.

---

## Stage 3 — Process injection

**Sysmon Event 8 (CreateRemoteThread).**

Having identified the victim process from Stage 2, filtering Event 8 on that process as
`TargetImage` surfaced the injector directly.

The injector was a legitimate Windows utility — a Living-off-the-Land Binary. It is
signed, it is present on every Windows host, and its execution is unremarkable in
isolation. What is not unremarkable is that binary creating a thread inside another
process.

**Query used:**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 8 } |
    Select-Object TimeCreated, @{n='Detail';e={$_.Message}} |
    Format-List
```

This is the pivot the whole investigation turns on: Event 8 links attacker-controlled
code back to the process that placed it there.

---

## Stage 4 — LSASS credential dumping

**Sysmon Event 10 (ProcessAccess).**

LSASS holds credential material in memory. Any process opening a handle to it with read
access is either endpoint protection or credential theft.

Filtering Event 10 with `lsass.exe` as `TargetImage` surfaced the responsible tool.

The critical follow-up question — and the one that determines incident severity — is
whether the dumped credentials were then *used*. Stolen credentials sitting unused are a
containable problem. Stolen credentials already used for lateral movement mean the blast
radius extends beyond this host.

**Follow-up query:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
    Where-Object { $_.TimeCreated -gt $dumpTime } |
    Select-Object TimeCreated, @{n='LogonType';e={$_.Properties[8].Value}}
```

Every Event 4624 after the dump timestamp was a routine SYSTEM service logon. **No
interactive or remote logon followed the credential theft** — the attacker had the
credentials but had not yet moved. Containment was still viable at the host level.

That negative finding is as valuable as any positive one. It is the difference between
"isolate this host" and "assume domain compromise."

---

## Stage 5 — PPID spoofing

**Sysmon Event 1 (ProcessCreate).**

The final stage showed a Windows error-reporting utility spawning `cmd.exe`, which then
ran `whoami`.

Error-reporting utilities do not open interactive shells. This is PPID spoofing — the
attacker set a trusted process as the parent of their payload so that any analyst
scanning the process tree sees a benign-looking lineage.

The tell was the **`whoami` command itself**: basic discovery, the first thing an operator
runs after establishing execution to find out what privileges they landed with.

The working directory tied it back to `C:\ProgramData` — the same staging path from
Stage 1, closing the loop and confirming a single actor across all five stages rather
than unrelated findings.

---

## Reconstructed attack chain

```
Stage 1  DLL search-order hijack        T1574.001   →  initial execution
   │                                                    staged in C:\ProgramData
   ▼
Stage 2  CLR loaded into unexpected     T1059.001   →  PowerShell capability
         process                                        without powershell.exe
   │
   ▼
Stage 3  CreateRemoteThread injection   T1055       →  code running inside a
                                                        trusted process
   │
   ▼
Stage 4  LSASS handle opened            T1003.001   →  credentials harvested
   │                                                    (not yet used)
   ▼
Stage 5  PPID-spoofed cmd.exe →         T1134.004   →  discovery, hidden behind
         whoami                          T1033         a trusted parent
```

---

## What I would do differently with production tooling

**Detections this would have caught earlier.** The three Sigma rules in
[`detection-engineering/`](../../detection-engineering/) were written directly from this
investigation. The [PPID spoofing rule](../../detection-engineering/sigma-rules/ppid-spoofing-unusual-parent.yml)
would have fired at Stage 5, the [LSASS rule](../../detection-engineering/sigma-rules/lsass-credential-access.yml)
at Stage 4, and the [DLL hijack rule](../../detection-engineering/sigma-rules/dll-hijack-nonstandard-path.yml)
at Stage 1 — turning a manual reconstruction into three alerts in chronological order.

**Telemetry gaps.** Sysmon Event 11 (FileCreate) was not reviewed and would have shown
the hijacked DLL being written to `C:\ProgramData` before it was ever loaded — a full
stage earlier than the earliest detection above. Command-line logging on Event 1 was
essential and would be worth confirming as enabled fleet-wide.

**Containment call.** With the Stage 4 negative result established, the correct action is
host isolation plus a forced credential reset for every account with a session on that
host — not a domain-wide reset. Getting that scoping right is the difference between a
two-hour incident and a two-day outage.

---

## Related material

- [Windows Event Logs & Finding Evil](../../htb-academy/windows-event-logs-finding-evil/) — the underlying module, with full walkthrough PDFs
- [Detection engineering](../../detection-engineering/) — the rules written from this investigation
