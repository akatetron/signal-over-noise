# Rule: Signed Windows Binary Loading a DLL from a User-Writable Path

**Platform:** Sigma — `image_load` (Sysmon Event 7)
**MITRE ATT&CK:** [T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
**Severity:** High
**Signal strength:** ●●○○ Installers create noise — the hardest of the ten to tune
**Rule ID:** `c14b8a63-2e70-4d95-8f3c-6a1029db47e5`

---

## What it detects

Windows resolves DLL dependencies by searching a defined order of directories. If an
attacker can write a malicious DLL into a directory that is searched **before** the one
holding the real library, a trusted signed executable will load it — and from then on
the malicious code runs with that binary's reputation and, often, its privileges.

The detection combines three conditions that are individually common and jointly rare:

1. the DLL is loaded **from a user-writable staging directory** (`ProgramData`, `Temp`,
   `Users\Public`, `AppData`);
2. the process loading it is a **trusted binary** in System32, SysWOW64 or Program Files;
3. the DLL has **weak metadata** — placeholder version `0.0.0.0`, no company name, or no
   signature.

Point three is what makes the rule usable. Legitimate software loaded from those paths
almost always carries real version metadata and a signature. A hand-built payload
usually does not, because filling that in is an extra step nobody bothers with.

## The logic

```yaml
detection:
  selection_path:
    ImageLoaded|contains:
      - 'C:\ProgramData\'
      - 'C:\Users\Public\'
      - '\AppData\Local\Temp\'
      - 'C:\Windows\Temp\'
  selection_trusted_loader:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  selection_weak_metadata:
    - FileVersion: '0.0.0.0'
    - Company: null
    - Signed: 'false'
  condition: selection_path and selection_trusted_loader and selection_weak_metadata
```

## Fields to pull on a hit

`Image` · `ImageLoaded` · `FileVersion` · `Company` · `Signed` · `Hashes`

`Hashes` is the field that makes triage tractable. Once you have the hash you can check
it against threat intelligence, and you can allowlist by hash rather than by path — which
is the difference between a safe exclusion and a hole.

## False positives and tuning

This is the noisiest rule in the set, and the honest reason it is only two bars.

| Source | Why it happens | What to do |
|---|---|---|
| Installers | Legitimately stage DLLs in Temp during setup | Correlate with a concurrent MSI/setup process and a short-lived path |
| In-house line-of-business software | Often ships unsigned DLLs | Baseline and **allowlist by hash**, never by path |

Allowlisting by path is the trap here. `C:\ProgramData\VendorName\` as an exclusion means
anything an attacker drops in that directory is invisible. Hash-based exclusions survive
that; they just cost more to maintain.

## Triage workflow

1. **Is there a concurrent installer?** An MSI or setup executable running in the same
   window, with the DLL path disappearing shortly after, is the benign pattern.
2. **How long has the file existed?** A DLL created minutes before the load is very
   different from one that has sat there since the software was installed.
3. **Check the hash.** Known-good vendor binary, known-bad, or never seen anywhere.
4. **Check what the loading process did next.** Network connections, child processes and
   registry persistence written straight after the load are the confirmation.

## Escalation criteria

| Finding | Action |
|---|---|
| DLL created within minutes of the load | **Escalate to T2** |
| Hash unknown to any intelligence source and unsigned | **Escalate to T2** |
| Loading process makes an outbound connection after the load | **Escalate to T2** |
| Concurrent signed installer, path cleaned up afterwards | Document and close |

## Testing it

Copy an unsigned test DLL with no version metadata into `C:\ProgramData\` and have a
System32 binary load it in a lab VM. Confirm the Sysmon Event 7 record carries
`Signed: false` and an empty `Company` field — if your Sysmon configuration does not
include hashing and signature fields for image loads, this rule cannot work, and
checking that is the real point of the test.

## Source

[`dll-hijack-nonstandard-path.yml`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/sigma-rules/dll-hijack-nonstandard-path.yml) — the rule as deployed.
