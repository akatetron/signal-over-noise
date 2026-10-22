# Rules: C2 Beacon Detection

**Platform:** Suricata — IDS/IPS (`http`, `tcp`, `tls`)
**MITRE ATT&CK:** [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) · [T1573 — Encrypted Channel](https://attack.mitre.org/techniques/T1573/) · [T1047 — WMI](https://attack.mitre.org/techniques/T1047/)
**Severity:** Critical (network)
**Signal strength:** ●●●○ Layered — each rule covers the others' blind spot
**SID range:** `9000001`–`9000004` (local rules)

---

## Why four rules instead of one

Command-and-control traffic is the one thing an intrusion cannot do without. It is also
the thing attackers put the most effort into disguising. No single detection approach
survives contact with a competent operator, so these four are deliberately built on
**different and independent properties** of the traffic:

| # | Approach | Matches on | Defeated by |
|---|---|---|---|
| 1 | Signature | Known payload content | Changing the default profile |
| 2 | Anomaly | Behavioural shape — size and cadence | Randomised jitter and padding |
| 3 | Fingerprint | The TLS handshake itself | Changing TLS library |
| 4 | Protocol | DCE/RPC lateral movement | Not a C2 rule — covers the spread |

An operator who defeats rule 1 by editing their malleable profile still trips rule 2.
One who randomises their beacon to defeat rule 2 still presents the same JA3 hash to
rule 3. That layering is the entire design.

## 1 — Signature: PowerShell Empire HTTP listener

```
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"C2 PowerShell Empire default HTTP listener beacon"; \
    flow:established,to_server; \
    http.method; content:"GET"; \
    http.uri; pcre:"/\/(login\/process|admin\/get|news)\.php$/"; \
    http.cookie; content:"session="; \
    classtype:trojan-activity; \
    sid:9000001; rev:1; )
```

Empire's default HTTP listener has a recognisable shape: a GET to one of three URI
patterns, carrying a session cookie. Matching **all three elements together** keeps false
positives near zero — any one of them alone would be ordinary web traffic.

Honest weakness: this is trivially defeated by an operator who changes the default
profile. It catches the unprepared, which is still worth having, but it is the reason
rules 2 and 3 exist.

## 2 — Anomaly: fixed-size repeating beacon

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"C2 possible fixed-size beacon - repeated identical payload length"; \
    flow:established,to_server; \
    dsize:312; \
    detection_filter:track by_src, count 5, seconds 60; \
    classtype:trojan-activity; \
    sid:9000002; rev:1; )
```

This rule matches **no content at all**. It matches shape: a payload of an exact size,
repeating more than five times in sixty seconds to the same destination.

Beaconing malware checks in on a timer with a near-constant payload size. Human-driven
traffic does not behave this way. Because there is no content match, this survives the
operator changing their profile entirely.

> **`dsize:312` is an example from a lab capture, not a universal constant.** This value
> must be retuned to the beacon size observed in your own environment before the rule
> means anything.

## 3 — Fingerprint: JA3 TLS hash

```
alert tls $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"C2 Sliver implant JA3 fingerprint match"; \
    ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1"; \
    classtype:trojan-activity; \
    sid:9000003; rev:1; )
```

JA3 hashes the client's TLS handshake parameters — version, cipher suites, extensions,
elliptic curves. Malware built against a particular TLS library produces a consistent
hash **regardless of what it is encrypting or which domain it fronts through**.

This is the highest-value technique in the file, because it detects encrypted C2 without
decrypting anything: no TLS interception, no privacy trade-off, no certificate warnings
for users.

Two caveats worth stating plainly. JA3 **collisions exist** — a hash shared with a common
Go or Python HTTP client will generate false positives, so validate against a baseline of
your own environment first. And fingerprints change with every implant release, so treat
the hash as a **perishable indicator**, not a permanent signature.

## 4 — Protocol: WMI remote execution

```
alert tcp $HOME_NET any -> $HOME_NET 135 ( \
    msg:"LATERAL possible WMI remote process execution"; \
    flow:established,to_server; \
    content:"|05 00 0b|"; depth:3; \
    content:"IWbemServices"; nocase; \
    classtype:attempted-admin; \
    sid:9000004; rev:1; )
```

Scoped internal-to-internal, because WMI over DCE/RPC is genuinely used by legitimate
management tooling. This one needs baselining against your known management servers
before it is useful. It pairs with the host-based
[WMI remote process execution](../sigma-rules/wmi-lateral-movement.md) Sigma rule — network
sees the connection, endpoint sees the spawned process.

## Deployment notes

1. **Never deploy inline on day one.** Run in IDS alert-only mode for a full business
   cycle first — including month-end, when batch jobs and reporting traffic look nothing
   like a normal Tuesday.
2. **Rule 2 must be retuned** per environment. See the warning above.
3. **Rule 3 needs a current hash.** Treat it as perishable.
4. **`$HOME_NET` must be defined accurately** in `suricata.yaml`. A misdefined `HOME_NET`
   is the single most common reason a correct rule silently never fires.

## Source

[`c2-beacon-detection.rules`](https://github.com/akatetron/signal-over-noise/blob/main/detection-engineering/suricata-rules/c2-beacon-detection.rules) — the rules as deployed, with full comments.
