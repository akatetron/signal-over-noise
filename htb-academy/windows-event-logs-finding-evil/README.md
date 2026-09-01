# 🟢 HTB Academy — Windows Event Logs & Finding Evil

**Module:** Windows Event Logs & Finding Evil · **Category:** DFIR / Blue Team · **Difficulty:** Medium

> Lab answers are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module simulates a full intrusion on a single Windows host, from an initial DLL hijack all the way through to credential dumping and a suspicious parent-child process relationship — and the job is to reconstruct every stage of the attack purely from Windows Event Logs and Sysmon telemetry, using PowerShell's `Get-WinEvent` and manual Event Viewer inspection rather than any EDR alert telling you where to look first. The five techniques covered — DLL hijacking, unmanaged PowerShell (CLR) injection, process injection via `CreateRemoteThread`, LSASS credential dumping, and PPID spoofing — are among the most common techniques a blue-team analyst will actually encounter, which is what makes this module a useful complement to the SIEM- and Splunk-based investigations elsewhere in this repo: the same underlying attacker behavior, hunted this time straight from raw event logs instead of an aggregation platform.

## Files in this folder

| File | Description |
|---|---|
| [`WinEventLogs_Walkthrough.pdf`](./WinEventLogs_Walkthrough.pdf) | Full illustrated walkthrough of all five techniques and their event-log evidence. Quick reference on the last page. |
| [`WinEventLogs_Student_Notes.pdf`](./WinEventLogs_Student_Notes.pdf) | Condensed study notes with the same reference on the first page. |
| `source-files/` | Original screenshots captured during the lab (Event Viewer, clr.dll load, rundll32 injection) |

Both PDFs share the same green / pink accent pair used throughout this folder.

---

## Complete walkthrough

### DLL hijack — a familiar technique from an unfamiliar angle

The chain starts with Sysmon Event 7 (ImageLoaded), which logs every DLL a process loads. A trusted Windows executable loading a DLL from `C:\ProgramData` instead of its expected `System32` path — with placeholder metadata (version `0.0.0.0`, no company name) — is the classic signature of a DLL hijack: an attacker plants a malicious DLL somewhere Windows' search order will find it before the real one.

### Unmanaged PowerShell and the process that injected it

The next stage looks for a process with no legitimate reason to run .NET code suddenly loading `clr.dll`, the .NET Common Language Runtime — a strong indicator of shellcode reflectively injected to run PowerShell-equivalent code without ever launching `powershell.exe` itself, evading detections that watch for that process by name. Once the victim process is identified, Sysmon Event 8 (CreateRemoteThread) — which fires whenever one process creates a thread inside another — is filtered to that victim as the `TargetImage`, surfacing the actual injector: a legitimate Windows utility being abused to run code while blending in with ordinary system activity.

### LSASS dumping and the post-dump login check

LSASS holds credentials in memory, and Sysmon Event 10 (ProcessAccess) logs any time one process opens another with read access — exactly what a credential-dumping tool does. Filtering that event to `lsass.exe` as the target surfaces the tool responsible. The follow-up question — whether the attacker used the dumped credentials to log in anywhere afterward — is answered by checking Windows Security Event 4624 (Logon) for any interactive or remote logon after the dump timestamp that isn't a routine SYSTEM service logon; in this case, none were found.

### PPID spoofing — a legitimate tool spawning a shell

The final technique is a strange parent-child relationship: Sysmon Event 1 (ProcessCreate) shows a Windows error-reporting utility — a process that has no business ever opening an interactive shell — spawning `cmd.exe` with a `whoami` command. That mismatch between a trusted parent process and an unexpected child process is exactly the pattern PPID-spoofing detection rules are built to catch, and the shared `C:\ProgramData` working directory ties this stage back to the same staging location used in the initial DLL hijack.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
