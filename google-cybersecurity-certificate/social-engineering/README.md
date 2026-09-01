# 🎭 Social Engineering

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Scenario:** USB baiting / "parking lot drop"

## What this lab was about

Social engineering attacks exploit human psychology rather than a technical vulnerability. This exercise analyzes a classic USB-baiting scenario: an employee finds a USB drive in a hospital parking lot, plugs it in out of curiosity, and the exercise works through what an attacker could actually do with the information on that device — and which technical, operational, and managerial controls would have mitigated the risk.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full analysis of the scenario from the finder's, attacker's, and defender's perspective. Quick reference on the last page. |
| `source-files/Parking lot USB exercise_.docx` | Original lab worksheet (given) |

## Complete walkthrough

The USB drive contains a mix of personal documents Jorge, the employee, wouldn't want made public, along with work files that include other people's PII and information about the hospital's operations. From an attacker's perspective, this isn't really about malware on the drive — it's intelligence. The timesheets and work files reveal who Jorge works with, and either the personal or professional information could be used to craft a convincing pretext, like a phishing email designed to look like it comes from a coworker or relative.

That reframing is the core lesson: the payload of a USB-baiting attack can be the *information* on the drive just as easily as any executable on it. Mitigating it takes controls at three levels — managerial (employee awareness training on what to do with a found or unknown USB drive), operational (routine antivirus scanning as standard procedure), and technical (disabling AutoPlay/AutoRun so a drive can't auto-execute anything the moment it's plugged in).

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
