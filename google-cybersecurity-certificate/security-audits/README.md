# 🔒 Security Audits — Botium Toys

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Framework:** NIST CSF — Identify function

## What this lab was about

A security audit reviews an organization's security controls, policies, and procedures against a set of expectations — in this case, a full NIST Cybersecurity Framework audit of Botium Toys, a toy retailer with both physical storefronts and e-commerce operations. The audit covers asset scope and an overall risk score, a detailed controls-and-compliance checklist against PCI DSS, GDPR, and SOC, and a set of prioritized hardening recommendations.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full audit — scope, risk assessment, compliance checklist, and hardening recommendations. Quick reference on the last page. |
| `source-files/Botium Toys_ Scope, goals, and risk assessment report.docx` | Original lab worksheet (given) |
| `source-files/Controls and compliance checklist_.docx` | Original lab worksheet (given) |
| `source-files/Security risk assessment report_.docx` | Original lab worksheet (given) |

## Complete walkthrough

The audit's scope is the entire security program at Botium Toys — employee equipment, the internal network, all systems, and the accounting, ecommerce, and inventory management platforms that run the business. Using the NIST CSF Identify function, the assessment landed on a risk score of 8/10 (High): asset management is inadequate, and multiple gaps put the company at risk of falling short of both U.S. and international compliance standards. Employees have unrestricted access to cardholder data and PII, credit card data isn't encrypted, there's no IDS, and no disaster recovery plan or backup strategy exists — while firewall, antivirus, and physical security controls are already solid.

The compliance checklist maps those same gaps against three specific standards. Against PCI DSS, the company fails on every measured practice — unauthorized access to cardholder data, no encryption, and a password policy below minimum requirements. Against GDPR, it's partially compliant: a 72-hour breach notification plan exists and privacy policies are enforced, but data isn't encrypted and asset classification is incomplete. Against SOC, it fails on user access policy and data confidentiality, though data integrity controls are in place. The hardening recommendations that follow are prioritized in the order they'd close the biggest gaps first: least privilege, encryption, separation of duties (notably, the CEO both runs operations and manages payroll — a built-in fraud risk), disaster recovery planning, an IDS deployment, and a centralized password management system enforcing MFA and strong password policy.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
