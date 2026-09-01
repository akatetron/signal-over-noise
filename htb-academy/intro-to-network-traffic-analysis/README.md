# 🟦 HTB Academy — Intro to Network Traffic Analysis

**Module:** Intro to Network Traffic Analysis · **Status:** 100% complete · **Track:** Network Traffic Analysis

> Lab answers are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module builds packet-analysis fluency from the ground up: the OSI/TCP-IP layers that make network traffic legible in the first place, then hands-on work in three tools that every SOC analyst ends up using — **TCPDump** for fast command-line capture and filtering, **Wireshark** for deep protocol dissection and GUI-based investigation, and **TShark** as Wireshark's scriptable command-line twin. The practical labs cover extracting files that were transferred in the clear over both HTTP (an embedded JPEG) and FTP (reconstructing a file from a raw TCP stream), analyzing a live-captured RDP session to identify a suspicious employee, and — in the module's most advanced section — decrypting a captured RDP session entirely by recovering and applying the server's private key in Wireshark.

---

## Files in this folder

| File | Description |
|---|---|
| [`NTA_Walkthrough.pdf`](./NTA_Walkthrough.pdf) | Full illustrated walkthrough — file extraction from HTTP/FTP, the live RDP investigation, and RDP decryption. Command index on the last page. |
| [`NTA_Student_Notes.pdf`](./NTA_Student_Notes.pdf) | Condensed study notes with a TCPDump/Wireshark command index on the first page. |
| `source-files/` | The original lab materials — capture files, extracted evidence images, and the RDP decryption key, exactly as provided by HTB Academy. |

Both PDF documents share the same teal / orange accent pair used throughout this folder.

---

## Complete walkthrough

### Why network traffic analysis matters

NTA is the discipline of examining traffic to characterize ports and protocols, establish a day-to-day baseline, and catch what deviates from it — suspicious hosts, non-standard ports, malformed HTTP, malware callbacks. It depends on a working knowledge of the TCP/IP stack and the OSI model, since every tool in this module is really just a different lens for reading the same layered headers as packets move across the wire.

### TCPDump — fast capture and filtering from the command line

TCPDump is the tool for quick, low-overhead capture directly on a host: `-i` to pick an interface, `-nn` to skip slow hostname/port resolution, `-XX` to see the Ethernet header plus hex and ASCII payload, and `-w`/`-r` to save and later replay a capture. Its filter syntax (`host`, `src`/`dst`, `port`, `portrange`, boolean `and`/`or`/`not`) is expressive enough to isolate a single conversation out of a busy interface, and it can even filter on raw TCP flag bytes — `tcp[13] & 2 != 0` catches SYN packets, which is the basis for detecting a port scan directly from the command line.

### Wireshark and TShark — deep protocol dissection

Where TCPDump filters at capture time, Wireshark's display filters (`ip.addr`, `tcp.port`, `dns`, `http`, `ftp-data`, `tcp.stream eq N`) let you slice an already-captured file any way you need after the fact, and its GUI makes following an entire TCP conversation — or reconstructing a file that was sent as raw stream data — a few clicks instead of manual byte-parsing. TShark exposes the same filtering engine from the command line, which matters when you need to script an analysis rather than click through it.

### File extraction — HTTP and FTP

The HTTP extraction lab filters for `http && image-jfif` to spot JPEG objects in the traffic, then uses Wireshark's **Export Objects → HTTP** feature to pull the actual image file straight out of the capture. The FTP lab works differently, since FTP data doesn't tag itself as conveniently: filtering on `ftp.request.command` shows what file operations occurred, then switching to the `ftp-data` filter and following that TCP stream — saved as **Raw** rather than as text — reconstructs the original transferred file byte-for-byte.

### Live capture and identifying a suspicious user

The module's live-capture exercise connects to a lab target over RDP, runs Wireshark directly on the live interface during the session, and follows an HTTP stream to identify which employee's activity looked malicious. Because the capture couldn't be exported out of that lab environment, the entire analysis had to happen inside the live session — a closer simulation of real live-response work than analyzing a pre-packaged PCAP file.

### Decrypting a captured RDP session

The most advanced section shows what's possible once an RDP server's private key has been recovered: adding it as an RSA key list entry in Wireshark's TLS protocol preferences (IP address, port 3389, key file) turns an otherwise opaque encrypted stream into fully readable RDP application data. `source-files/server.key` is the lab's own teaching key, provided by HTB specifically for this exercise against a training capture — not a live credential.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
