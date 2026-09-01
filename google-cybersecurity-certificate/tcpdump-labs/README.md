# 💻 tcpdump Labs

**Track:** Google Cybersecurity Professional Certificate · **Course:** Detection and Response · **Tool:** tcpdump (command-line packet analyzer)

## What this lab was about

tcpdump is a command-line packet analyzer widely used in SOC environments for incident investigation when a GUI tool like Wireshark isn't available or a quick command-line capture is more practical. This exercise reads a raw tcpdump log line by line to trace a malware-delivery incident from its first DNS lookup, through the HTTP download, to a redirect toward a spoofed lookalike domain.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full walkthrough of the tcpdump log with every stage of the redirect chain explained. TCP flag reference on the last page. |
| `source-files/Copy of How to read the tcpdump traffic log.docx` | Original reading — how to interpret tcpdump output (given) |
| `source-files/Copy of tcpdump traffic log to read.docx` | Original raw tcpdump log data (given) |

## Complete walkthrough

The log opens with a DNS resolution: the source machine queries `dns.google.domain` for `yummyrecipesforme.com` and gets back `203.0.113.22`. A TCP handshake follows (`Flags [S]` → `[S.]` → `[.]`), and then an HTTP GET request — the actual file download that later slowed down victims' machines. Two minutes later, the same source machine makes a fresh DNS query, this time for `greatrecipesforme.com`, resolving to a completely different IP (`192.0.2.172`), and opens a new connection to it on a new source port.

That pivot — from the original domain to a near-identical lookalike, on a fresh connection — is the redirect chain: the downloaded file, disguised as a browser update, sent the victim's browser to a spoofed site. Combined with the site owner being locked out of their own admin account, the pattern points to an attacker who brute-forced the admin credentials and then modified the original site to serve the malicious download and redirect. The TCP flag codes that make a log like this readable are worth knowing cold: `[S]` starts a connection, `[S.]` is the SYN-ACK response, `[.]` acknowledges, `[P.]` pushes data, `[F]` finishes a connection, and `[R]` resets one.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
