# 🚨 Incident Response

**Track:** Google Cybersecurity Professional Certificate · **Course:** Detection and Response · **Framework:** NIST Incident Response Lifecycle

## What this lab was about

Incident response is the structured process of identifying, containing, and recovering from a security incident. This folder collects three separate incident write-ups covering three very different incident types: a SYN flood denial-of-service attack diagnosed from packet logs, a ransomware incident documented using the 5 W's framework, and an HTTP-based malware delivery investigation that traces back to a brute-forced admin account.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | All three incident reports in full, with the NIST IR lifecycle and 5 W's framework applied throughout. Quick reference on the last page. |
| `source-files/Security incident report_ read the tcpdump traffic log_.docx` | Original lab worksheet — SYN flood report (given) |
| `source-files/Cybersecurity incident report _Analyze network attacks.docx` | Original lab worksheet — malware delivery report (given) |

## Complete walkthrough

The first report investigates a SYN flood DoS attack: the web server stopped responding after being overloaded with SYN packet requests, and the underlying mechanism is the same one covered in more packet-level detail in the Wireshark Labs and tcpdump Labs folders — an attacker floods SYN requests without ever completing the handshake, exhausting the resources the server reserves for each pending connection.

The second is an Incident Handler's Journal entry documenting a ransomware attack at a healthcare company, built around the 5 W's: **who** (an organized group of unethical hackers), **what** (a ransomware incident), **where** (the healthcare company itself), **when** (Tuesday, 9:00 a.m.), and **why** (initial access via phishing, followed by ransomware deployment for what appears to be a financially motivated extortion attempt). The entry flags two open questions typical of the first 72 hours of a real incident: how to prevent a repeat, and whether to pay the ransom.

The third report investigates HTTP-based malware delivery on `yummyrecipesforme.com`: customers downloaded a file disguised as new recipe content, their machines slowed afterward, and the site owner found themselves locked out of the admin account. Investigating in a sandboxed environment with tcpdump running, the analyst replicated the download and watched the browser redirect to a spoofed lookalike domain, `greatrecipesforme.com`. The most likely root cause is a brute-forced admin password used to inject the malicious redirect into the original site — which is exactly why the recommended remediations center on stronger password requirements and mandatory 2FA.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
