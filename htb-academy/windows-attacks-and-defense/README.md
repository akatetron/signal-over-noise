# 🔵 HTB Academy — Windows Attacks & Defense

**Module:** Windows Attacks & Defense · **Environment:** EAGLE.LOCAL Active Directory domain · **Track:** Red/Blue Windows

> Lab answers are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module pairs an attack with its detection, twice over, inside a live Active Directory domain. The first pairing hunts for one of the most avoidable AD misconfigurations there is: administrators leaving clear-text passwords in a user account's Description or Info field, found here with a PowerShell script that filters every AD user against a list of suspicious terms, and confirmed by cross-referencing Windows Security Event 4771 (Kerberos pre-authentication failure) to resolve that account's SID. The second, more advanced pairing performs a full **DCSync attack** — abusing the legitimate AD replication protocol via mimikatz to pull the domain Administrator's password hash directly from a domain controller, with no code execution on the DC required — and then finds the specific Windows Security event (4662, Directory Service Access) that's the actual detection artifact for it.

---

## Files in this folder

| File | Description |
|---|---|
| [`WinAttackDefence_Walkthrough.pdf`](./WinAttackDefence_Walkthrough.pdf) | Full illustrated walkthrough of both attack/detection pairs. Quick reference on the last page. |
| [`WinAttackDefence_Student_Notes.pdf`](./WinAttackDefence_Student_Notes.pdf) | Condensed study notes with the same reference on the first page. |

Both documents share the same blue / rose accent pair used throughout this folder.

---

## Complete walkthrough

### Hunting clear-text credentials in AD attributes

AD account objects have free-text Description and Info fields that exist for administrative notes — and are occasionally misused to store exactly what they shouldn't. A PowerShell script pulls every AD user via `Get-ADUser -Filter *`, builds a dynamic `-OR` filter from a list of suspicious search terms (things like "pass"), and searches both fields for a match. Running it against this domain immediately surfaces a user account with a password sitting in plaintext in its Description field — and that account also has `PasswordNeverExpires` set to true, meaning the exposure doesn't self-heal the way an expiring password eventually would.

### Confirming an account's identity through Kerberos events

Windows Security Event 4771 ("Kerberos pre-authentication failed") logs the target username and, critically, its full Security Identifier (SID) whenever a pre-auth attempt fails. That matters because Windows access control is entirely SID-based under the hood — usernames can be renamed, but the SID is the permanent identifier tied to every permission and group membership an account holds, which makes resolving a suspicious username to its SID a standard step before digging further into what that account can actually access.

### DCSync — abusing legitimate replication, not a vulnerability

DCSync doesn't exploit a bug; it abuses a legitimate feature. Any account holding the Replicating Directory Changes / Replicating Directory Changes All permissions — normally reserved for domain controllers themselves — can ask a real DC to "replicate" any account's password data directly to it, exactly as if it were another DC. Running `lsadump::dcsync` in mimikatz against the domain Administrator account, from a compromised account holding those replication rights, returns the Administrator's NTLM hash and Kerberos key material without ever touching the DC's disk or triggering a traditional malware alert — which is exactly what makes it one of the highest-value single actions available to an attacker who has compromised the right account, and one of the harder techniques to catch by signature alone.

### Catching DCSync in the event log

Because DCSync rides on a legitimate protocol, detecting it means watching for the replication *request* itself rather than any malicious payload. Windows Security Event 4662 ("An operation was performed on an object"), filtered to a Directory Service Access task category against the domain root object itself (`DC=eagle,DC=local`) from an account that isn't one of the actual domain controllers, is the specific pattern that catches it — the target object being replication-relevant, combined with the requesting account's identity, is what separates this from routine, benign directory access.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
