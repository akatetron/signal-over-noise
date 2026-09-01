# 🌐 Network Traffic Analysis — DNS & ICMP

**Track:** Google Cybersecurity Professional Certificate · **Course:** Detection and Response · **Tool:** tcpdump

## What this lab was about

Network traffic analysis means inspecting packet-level data to identify anomalies, diagnose outages, and detect attacks. This exercise diagnoses a specific DNS outage from a tcpdump capture — recognizing the ICMP "port unreachable" error pattern that shows up when a DNS server stops responding, and narrowing the root cause down to two candidate explanations: the DNS server itself being down, or a firewall rule blocking port 53.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full incident report covering the DNS/ICMP evidence and next investigative steps. Quick reference on the last page. |
| `source-files/Cybersecurity Incident Report_ Network Traffic Analysis_.docx` | Original lab worksheet (given) |

## Complete walkthrough

Every event in the capture follows the same shape: an outbound UDP query to the DNS server requesting an A record for `yummyrecipesforme.com`, followed immediately by an ICMP error — `udp port 53 unreachable`. That consistent pattern across the whole log, rather than a one-off blip, is what confirms this is a systemic DNS problem rather than a transient network hiccup.

The incident was first reported at 1:24 p.m. after customers started seeing "destination port unreachable" errors trying to reach the website. tcpdump packet sniffing confirmed the port-53 unreachable pattern, but two plausible root causes remain open at this stage: either a denial-of-service attack took the DNS server itself offline, or a firewall misconfiguration is blocking port 53 traffic before it reaches the server at all. Distinguishing between those two is the next investigative step — checking whether the DNS server process is actually up settles it either way.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
