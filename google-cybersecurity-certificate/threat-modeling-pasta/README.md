# 🍝 Threat Modeling — PASTA

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Framework:** PASTA — 7 stages

## What this lab was about

PASTA (Process for Attack Simulation and Threat Analysis) is a risk-centric threat modeling framework that runs through seven stages, from business objectives all the way to concrete risk analysis and security controls. This exercise applies the full framework to a sneaker company's mobile app — a system that handles member profiles, financial transactions, and must stay PCI-DSS compliant — with the API surface identified early as the highest-priority component to analyze.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full 7-stage PASTA model with every stage's findings. Quick reference on the last page. |
| `source-files/PASTA worksheet_.docx` | Original lab worksheet (given) |
| `source-files/PASTA data flow diagram.pptx` | Original data flow diagram (given) |
| `source-files/PASTA attack tree.pptx` | Original attack tree diagram (given) |

## Complete walkthrough

Stage I defines the business and security objectives: users can build profiles internally or via connected external accounts, the app processes financial transactions, and it must remain PCI-DSS compliant. Stage II scopes the technology involved — API, PKI, SHA-256, and SQL — and prioritizes the API for deeper analysis, since it's the piece connecting multiple systems and users while handling sensitive data across the largest attack surface. Stage III decomposes the application into a data flow diagram showing how information actually moves between users, systems, and APIs.

Stage IV identifies the threat types that matter most given that scope: injection (malicious input like SQL injection exploiting unsanitized queries) and session hijacking (an attacker intercepting a valid session token to impersonate a legitimate user). Stage V ties those threats to concrete vulnerabilities — a lack of prepared statements leaving SQL queries open to injection, and improperly validated or expired API tokens. Stage VI models the actual attack paths in an attack tree, and Stage VII closes the loop with security controls: SHA-256 hashing for sensitive data, defined incident response procedures, a strong password policy, and the principle of least privilege applied throughout.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
