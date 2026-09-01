# 🔐 Cryptography

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Environment:** Linux Bash shell

## What this lab was about

Two hands-on Linux labs covering two different pillars of cryptography: file integrity verification with SHA-256 hashing, and a three-stage decryption puzzle that chains a Caesar cipher into an AES-256-CBC decryption. Both labs are run entirely from the command line, which makes the underlying mechanics — hash comparison, character substitution, symmetric decryption — visible step by step rather than hidden behind a GUI.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full walkthrough of both labs with every command and its output. Quick reference on the last page. |
| `source-files/Generate hashes for files.docx` | Original lab worksheet (given) |
| `source-files/Caesar cipher lab_.docx` | Original lab worksheet (given) |

## Complete walkthrough

### Lab 1 — generating and comparing file hashes

Two files, file1.txt and file2.txt, both contain the EICAR antivirus test string and look byte-for-byte identical when printed with `cat`. Running `sha256sum` on each produces two completely different digests, proving the files aren't actually the same despite looking it — exactly why integrity checks lean on cryptographic hashes rather than visual inspection. Writing both hashes to separate files and comparing them with `cmp` confirms the two differ starting at the very first character.

### Lab 2 — Caesar cipher into AES-256-CBC

The home directory contains an encrypted file (`Q1.encrypted`), a README pointing toward a hidden subdirectory, and inside that subdirectory a hidden file — `.leftShift3` — encrypted with a classic Caesar cipher. Piping its contents through `tr "d-za-cD-ZA-C" "a-zA-Z"` shifts every letter three positions back in the alphabet and reveals the plaintext instruction: an `openssl aes-256-cbc` command with the decryption key baked in. Running that command against `Q1.encrypted` recovers the original message. The layering mirrors how a real ransomware note or CTF challenge might be structured — a weak cipher gating access to the real key needed for a strong one.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
