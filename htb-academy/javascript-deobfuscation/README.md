# 🟣 HTB Academy — JavaScript Deobfuscation

**Module:** [JavaScript Deobfuscation (#41)](https://academy.hackthebox.com/module/details/41) · **Status:** 100% complete · **Track:** Malware Analysis / Blue Team

> Flags below are partially masked (first, middle, and last character shown as a hint) in line with HTB Academy's guidance on not publishing exact answers.

---

## What this lab was about

This module teaches the workflow a SOC analyst or malware analyst uses when they run into obfuscated JavaScript in the wild — which happens constantly, since it's one of the most common ways attackers hide C2 callback URLs, dropper logic, and exfiltration endpoints from both automated tools and human reviewers. The module walks through recognizing the common obfuscation patterns (minification, Dean Edwards packing, obfuscator.io string arrays, JSFuck), unpacking and beautifying them with online tools, reading the deobfuscated code to understand what it actually does, and then manually replicating its behavior with `curl` to see what a hidden server endpoint returns. It closes with a multi-stage skills assessment that chains all of it together: find the script, deobfuscate it, decode the response it triggers, and use that decoded value to unlock the next stage. It's a compact but realistic simulation of triaging a suspicious script found on a compromised or malicious page.

---

## Files in this folder

| File | Description |
|---|---|
| [`JS_Deobfuscation_Walkthrough.pdf`](./JS_Deobfuscation_Walkthrough.pdf) | Full illustrated walkthrough — the identification guide, step-by-step workflow, and the complete skills assessment. Command reference on the last page. |
| [`JS_Deobfuscation_Student_Notes.pdf`](./JS_Deobfuscation_Student_Notes.pdf) | Condensed study notes with a command & tool index on the first page for fast lookup. |

Both documents share the same violet accent color used throughout this folder.

---

## Complete walkthrough

### 1. What obfuscation is, and why attackers use it

Obfuscation isn't encryption — the code runs exactly the same, it's just transformed to be very hard for a human to read at a glance. Attackers use it to hide malware payloads from analysts and AV, evade signature-based IDS/IPS detection, and (less maliciously) legitimate developers use it to slow down reverse engineering of proprietary logic. Four patterns show up constantly: **minification** (everything on one line, common in production `.min.js`), **packing** via the Dean Edwards `eval(function(p,a,c,k,e,d){...})` wrapper (the most common type encountered in the wild), **obfuscator.io** output (`_0x`-prefixed variable names with Base64-encoded string arrays), and **JSFuck** (code written using only six characters — `[ ] ( ) ! +` — extremely verbose but effective at bypassing naive filters).

### 2. The deobfuscation workflow

The same five-step process applies almost every time: **locate** the script (`Ctrl+U` to view page source, look for `<script src="...">` tags), **identify** the obfuscation type by spotting the signature (the `eval(` wrapper gives away a packer immediately), **beautify** first using a formatter like prettier.io or beautifier.io (this only reformats — it does not unpack anything), **unpack** using a tool matched to the obfuscation type (matthewfl.com's UnPacker handles the Dean Edwards packer specifically), and finally **verify** the result by running it in jsconsole.com to confirm it still behaves the same way.

In this lab, that workflow led to a file called `secret.js`, identified as Dean Edwards packed code. Unpacking it revealed a `generateSerial()` function containing a flag variable in plaintext and an `XMLHttpRequest` POSTing to `/serial.php` with no body — meaning the endpoint accepts empty requests and presumably returns something useful.

### 3. Encoding and decoding — Base64, hex, and ROT13

Once you can trigger a hidden endpoint, its response is often encoded rather than obfuscated — a different problem with different tells. **Base64** uses only alphanumeric characters plus `+`, `/`, and `=` padding, and its output length is always a multiple of 4 (`echo "..." | base64 -d` to decode). **Hex** uses only `0-9` and `a-f`, always in pairs (`echo "..." | xxd -p -r` to decode). **ROT13** shifts every letter 13 places, so it still has recognizable English shape — `http://www` becomes `uggc://jjj` — and conveniently, the exact same `tr` command both encodes and decodes it, since applying a 13-place shift twice returns the original text.

### 4. Replicating hidden functions with curl

Once a script's behavior is understood, the fastest way to explore what a server endpoint actually does is to bypass the browser entirely and call it directly with `curl` — `curl -s http://target/endpoint -X POST` replicates an empty POST, `-d "key=value"` attaches form data, and `-v` shows full request/response headers when something isn't behaving as expected. In this lab, POSTing to `/serial.php` returned a Base64-encoded string; decoding it and POSTing the decoded value back returned the flag `HTB{j•••••••••••••r•••••••••••l}`.

### 5. Skills assessment — full chain

The closing assessment strings every technique together against a live target:

1. **Find the script** — view-source revealed `<script src="api.min.js"></script>`.
2. **Run it as-is** — pasting `api.min.js` straight into jsconsole.com executed a `console.log()` that printed a flag: `HTB{j•••••••••••••m•••••••••••••y}`.
3. **Deobfuscate it properly** — running it through UnPacker revealed a `flag` variable in plaintext: `HTB{n•••••••••••••u•••••••••••!}`, plus an `xhr.open('POST', '/keys.php', true)` call pointing to a second hidden endpoint.
4. **Replicate the POST** — `curl -s http://target/keys.php -X POST` returned a hex-encoded string (a value starting `4...` and ending `...e`).
5. **Decode and complete the chain** — decoding that hex string with `xxd -p -r` produced an API key (`A••••••••7•••••••••n`), which, POSTed back to `/keys.php`, returned the final flag: `HTB{r•••••••••••••m•••••••••••••B}`.

That last step is the real point of the exercise: real malware very often works exactly this way — obfuscation, then an encoded response, then another request, then another decode — and being comfortable chaining several small techniques together is what separates "I can decode Base64" from "I can actually triage a malicious script."

### 6. Key takeaways for blue-team work

The `eval(function(p,a,c,k,e,d){...})` signature always means Dean Edwards packing — run it through UnPacker first. `_0x`-prefixed variable names are a reliable tell for obfuscator.io output. Base64 is spotted by its `=`/`==` padding, hex by its restricted `0-9a-f` character set, and ROT13 by text that still "looks like" scrambled English. Always re-verify deobfuscated code in jsconsole.com before trusting your read of it, and remember that any `XHR`/`fetch` call in client-side JavaScript can be replicated by hand with `curl` — which is often the fastest way to find a server endpoint the front end never surfaces directly.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · HackTheBox Academy*
