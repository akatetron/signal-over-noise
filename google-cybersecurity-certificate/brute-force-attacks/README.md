# 🔓 Brute Force Attacks

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Focus:** Credential attacks & defenses

## What this lab was about

Brute force attacks guess login credentials through systematic trial and error, and automated tooling turns what would take a human years into a matter of seconds. This exercise covers the tools most commonly used to run these attacks — Aircrack-ng, Hashcat, John the Ripper, Ophcrack, and THC Hydra — and the layered defenses (hashing and salting, MFA, CAPTCHA, and password policy) that make brute forcing impractical against a properly defended target.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full write-up of brute force tools and defenses. Quick reference on the last page. |
| `source-files/Brute FOrce_.docx` | Original lab worksheet (given) |

## Complete walkthrough

A brute force attack systematically tries every possible character combination until it finds the right one. Security professionals use the same tools attackers do — Aircrack-ng for Wi-Fi testing, Hashcat and John the Ripper for hash cracking, Ophcrack for Windows rainbow-table attacks, and THC Hydra for online service brute-forcing — the difference is authorization, not capability.

The defenses stack rather than substitute for each other. Hashing converts a password into a fixed-length value that can't be reversed, and salting adds random data before hashing so precomputed dictionary and rainbow-table attacks stop working. MFA means a successfully guessed password still isn't enough on its own, since the attacker also needs the second factor. CAPTCHA blocks the automated scripts that make brute forcing fast in the first place. And password policy — minimum complexity, lockout after N failed attempts, periodic changes, no reuse of recent passwords — closes off the weakest, most guessable credentials before an attacker ever gets to try them.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
