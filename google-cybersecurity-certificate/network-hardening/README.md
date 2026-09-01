# 🛡️ Network Hardening

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Focus:** Attack surface reduction

## What this lab was about

Network hardening is the set of controls that shrink how many ways an attacker can get into a network — tightening configuration, closing unnecessary exposure, and keeping systems current. This exercise surveys the core hardening tasks: baseline configuration management, firewall and patch maintenance, MFA, port filtering, network access privilege management, and password policy aligned to current NIST guidance.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full breakdown of each hardening task and what it defends against. Quick reference checklist on the last page. |
| `source-files/Network hardening tools.xlsx` | Original lab spreadsheet (given) |

## Complete walkthrough

Each hardening task in this lab targets a different layer of exposure. Baseline configuration management keeps a documented, approved standard so unauthorized changes or misconfigurations are easy to spot against it. Firewall maintenance and patch management keep the network's defenses current against both known traffic threats and known vulnerabilities. MFA adds a verification factor that's independent of password strength, while port filtering and disabling unused ports close off access points that have no active business justification. Network access privilege management ties access levels to actual role requirements, and password policy — informed by current NIST guidelines — sets the baseline for credential strength across the network.

None of these controls works as a silver bullet in isolation; hardening is cumulative. A fully patched, firewalled host that still has an unused port open and a weak password policy is meaningfully exposed regardless of how well the other controls are implemented.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
