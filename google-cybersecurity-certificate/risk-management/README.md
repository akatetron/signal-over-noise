# 📊 Risk Management

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Framework:** Likelihood × Severity risk matrix

## What this lab was about

Risk management means identifying threats to an organization's assets, scoring them consistently, and prioritizing which ones actually need attention first. This exercise builds a full risk register for a bank — five distinct risks to its funds, each scored by likelihood and severity — and pairs it with a smaller home asset inventory exercise that applies the same sensitivity-classification thinking at a household scale.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full risk register, scoring matrix, and asset inventory writeup. Quick reference on the last page. |
| `source-files/Risk register_.docx` | Original lab worksheet (given) |
| `source-files/Home asset inventory_.xlsx` | Original lab spreadsheet (given) |

## Complete walkthrough

The bank in scope sits in a low-crime coastal area, employs 100 on-premise and 20 remote staff, and serves 2,200 accounts across individual and commercial customers — all under strict financial regulation requiring secured data and adequate daily cash reserves. Five risks were scored against its funds using Priority Score = Likelihood × Severity (each rated 1–3): a business email compromise scored 4, a poorly encrypted customer database scored 6, physical theft from an unlocked safe scored 3, and supply chain disruption from natural disasters scored 2. The standout is a financial records leak — a backup database server left publicly accessible — which scored the maximum 9 and was flagged for immediate remediation, well above the lower-priority physical theft risk that the bank's low-crime location already partially mitigates.

The companion home asset inventory exercise scales the same discipline down to a single household: cataloging personal devices, accounts, and documents, then classifying each by sensitivity level using a structured framework rather than an ad-hoc list. The underlying principle is identical to the bank register — nothing can be prioritized for protection until it's been inventoried and ranked by how sensitive or critical it actually is.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
