# 🔴 HTB Academy — Working with IDS/IPS

**Module:** Working with IDS/IPS (#226) · **Status:** 100% complete · **Track:** Detection Engineering

> Lab answers are partially masked below as a hint, in line with HTB Academy's guidance on not publishing exact graded answers.

---

## What this lab was about

This module is a hands-on tour of the three tools that sit at the core of network security monitoring: **Suricata** and **Snort 3** as IDS/IPS engines, and **Zeek** as a network-monitoring log generator. It starts with the conceptual split between IDS (passive, out-of-band, alert-only) and IPS (active, inline, can drop traffic), then moves into writing real detection rules against real malware and C2 frameworks — PowerShell Empire, Covenant, Sliver, Cerber ransomware, and a Patchwork APT campaign — using both signature-based content matching and anomaly-based detection like beacon-size thresholds. It also covers JA3 TLS fingerprinting, which detects encrypted C2 traffic without decrypting it, and closes with three independent skills assessments across all three tools: a Suricata rule for WMI-based lateral movement, a Snort detection for an Overpass-the-Hash Kerberos attack, and a Zeek investigation into a malicious TLS certificate.

---

## Files in this folder

| File | Description |
|---|---|
| [`IDS_IPS_Walkthrough.pdf`](./IDS_IPS_Walkthrough.pdf) | Full illustrated walkthrough — every detection rule written in the module, with the reasoning behind each option. Command index on the last page. |
| [`IDS_IPS_Student_Notes.pdf`](./IDS_IPS_Student_Notes.pdf) | Condensed study notes with a Suricata/Snort/Zeek command index on the first page. |

Both documents share the same red / sky-blue accent pair used throughout this folder.

---

## Complete walkthrough

### IDS vs. IPS, and how detection actually works

An IDS sits passively out-of-band and only alerts; an IPS sits inline, in the direct path of traffic, and can actively drop packets or reset connections — which also means it carries a much higher cost when it gets a detection wrong. Three detection methods run underneath both: **signature-based** (matches known patterns — precise, but blind to zero-days), **anomaly-based** (flags deviation from a baseline — catches unknowns, at the cost of more false positives), and **stateful protocol analysis** (tracks protocol state to catch misuse). Real environments layer all three.

### Suricata — rules, output, and the anatomy of a detection

Suricata rules follow a consistent shape: `action protocol src_ip src_port -> dst_ip dst_port (options;)`. The module builds several real detections around this structure, including a rule for **PowerShell Empire** C2 traffic that matches on HTTP method, a URI pattern via PCRE, and a cookie field simultaneously; an **anomaly-based** rule for Covenant C2 that flags a specific payload size (`dsize:312`) repeated multiple times within a window (`detection_filter`) rather than matching any specific content at all; and a rule for **Sliver** C2 that matches purely on a JA3 hash — meaning it detects the C2 channel from its encrypted TLS handshake fingerprint without ever needing to decrypt the traffic. Suricata's `eve.json` output captures everything (alerts, DNS, HTTP, TLS, extracted files) in one JSON stream that's naturally filterable with `jq`.

### Snort 3 and the sticky-buffer trap

Snort 3 rules follow similar syntax to Suricata but aren't identical, and the module deliberately surfaces one of the most common mistakes an analyst can make: HTTP sticky buffers are tool-specific. `http_header;` is the correct keyword for a Snort rule targeting a header field, while `http_user_agent;` is Suricata's equivalent syntax — use the wrong one in the wrong engine and the rule simply never fires, silently, with no error. The module's Patchwork APT detection rule and a Cerber ransomware UDP beacon rule (matched on payload size, content, and a PCRE pattern, thresholded with `detection_filter`) both live in Snort and use this correct, tool-specific syntax.

### Zeek — structured logs for everything

Where Suricata and Snort are built around alerting, Zeek's job is comprehensive, structured logging: `conn.log` for every connection, `dns.log` for every query, `ssl.log` and `x509.log` for TLS session metadata and certificate details, and — critically for incident response — `dce_rpc.log`, which captures WMI and other DCE/RPC traffic and is one of the first places to look during a Windows lateral-movement investigation. `zeek-cut` pulls specific fields out of any log for fast filtering, and the `ja3` tool calculates the same TLS fingerprints Suricata rules can match against, directly from a PCAP.

### Skills assessment — three independent detections

The closing assessment removes the guided walkthrough and asks for three real detections built from scratch: a Suricata rule that catches WMI-based process execution (the `wmiexec` lateral-movement technique), a Snort-based detection for an Overpass-the-Hash attack visible through its Kerberos encryption type, and a Zeek-based investigation that pulls a malicious certificate's Common Name out of `x509.log`. The specific field values and answers are masked in the documents above per HTB's guidance, but the detection logic behind each is written out in full.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
