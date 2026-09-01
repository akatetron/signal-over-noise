# 🦈 Wireshark Labs

**Track:** Google Cybersecurity Professional Certificate · **Course:** Detection and Response · **Tool:** Wireshark (GUI packet analyzer)

## What this lab was about

Wireshark is a graphical packet analyzer used to capture and inspect network traffic in detail. This folder covers two connected exercises: filtering and drilling into a sample packet capture to understand a user's web browsing session at the protocol layer (IP, MAC, DNS, TCP), and reading a separate TCP/HTTP traffic log closely enough to recognize a SYN flood denial-of-service attack developing in real time against a company web server.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full walkthrough of both exercises with every filter used and the SYN flood pattern explained. Quick reference on the last page. |
| `source-files/Analyze your  packet with Wireshark.docx` | Original lab worksheet (given) |
| `source-files/Copy of How to read a Wireshark TCP_HTTP log.docx` | Original reading — how to interpret the log (given) |
| `source-files/Wireshark TCP_HTTP log for Analyze network attacks.xlsx` | Original TCP/HTTP log data (given) |

## Complete walkthrough

The first exercise works through Wireshark's core filtering vocabulary — `ip.addr`, `ip.src`, `ip.dst` for IP-based filtering, `eth.addr` for MAC-based filtering, `udp.port == 53` for DNS traffic, `tcp.port == 80` for HTTP, and `tcp contains "text"` for searching payload content directly. Drilling into a single packet's subtrees (Frame → Ethernet II → Internet Protocol Version 4 → Transmission Control Protocol) walks through each network layer for that packet in turn, from the raw frame up to the transport-layer flags and ports.

The second exercise reads a TCP/HTTP log for traffic between employee visitors and a company web server (`192.0.2.1`). Normal traffic shows the standard three-way handshake — `[SYN]` → `[SYN, ACK]` → `[ACK]` — followed by a clean HTTP GET and 200 OK. Against that baseline, one source IP (`203.0.113.0`) stands out: it sends `[SYN]` after `[SYN]` without ever completing the handshake, tying up server resources reserved for each one. As the flood continues, legitimate visitors start seeing `504 Gateway Time-out` errors and `[RST, ACK]` resets, and by the later log entries the server stops responding to anyone but the attacker — a single source IP, which marks this as a direct (not distributed) SYN flood DoS attack.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
