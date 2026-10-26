#!/usr/bin/env python3
"""Validate the detection rules in this repo and print an ATT&CK coverage table.

Checks
  Sigma  (detection-engineering/sigma-rules/*.yml)
    - parses as YAML, has title/id/status/description/author/date/logsource/detection/level/tags
    - id is a valid UUID and unique, level is a valid Sigma level
    - every name used in `condition` exists in `detection`
    - falsepositives is present and non-empty (every rule must ship tuning notes)
    - has at least one attack.tXXXX technique tag
  KQL / SPL write-ups (kql-hunts/*.md, splunk-spl/*.md)
    - declare a '**MITRE ATT&CK:**' technique and include false-positive notes
  Suricata (detection-engineering/suricata-rules/*.rules)
    - every rule has msg, sid and rev, and sids are unique
Exit code is 1 if any check fails.
"""
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "detection-engineering" / "sigma-rules"
SURICATA_DIR = ROOT / "detection-engineering" / "suricata-rules"
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "logsource", "detection", "level", "tags"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "(", ")"}

errors = []
coverage = {}  # technique -> list of rule names


def err(path, msg):
    errors.append(f"{path.relative_to(ROOT)}: {msg}")


def check_sigma(path, seen_ids):
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        err(path, f"invalid YAML ({e})")
        return
    if not isinstance(rule, dict):
        err(path, "not a YAML mapping")
        return
    for key in REQUIRED:
        if not rule.get(key):
            err(path, f"missing required field '{key}'")
    rid = str(rule.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        err(path, f"id '{rid}' is not a valid UUID")
    if rid in seen_ids:
        err(path, f"duplicate id (also in {seen_ids[rid]})")
    seen_ids[rid] = path.name
    if str(rule.get("level", "")).lower() not in LEVELS:
        err(path, f"level '{rule.get('level')}' is not a Sigma level")
    if not rule.get("falsepositives"):
        err(path, "no falsepositives / tuning notes")
    det = rule.get("detection") or {}
    cond = str(det.get("condition", ""))
    if not cond:
        err(path, "detection has no condition")
    names = {k for k in det if k != "condition"}
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", cond):
        if tok.lower() in KEYWORDS:
            continue
        if "*" in tok:
            if not any(n.startswith(tok.rstrip("*")) for n in names):
                err(path, f"condition pattern '{tok}' matches no selection")
        elif tok not in names:
            err(path, f"condition references undefined selection '{tok}'")
    techs = [m.group(1).upper() for t in rule.get("tags", [])
             if (m := TECH.match(str(t)))]
    if not techs:
        err(path, "no attack.tXXXX technique tag")
    for t in techs:
        coverage.setdefault(t, []).append(rule.get("title", path.stem))


def logical_lines(text):
    """Join Suricata rules split across lines with a trailing backslash."""
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        stripped = raw.strip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        yield start, buf
        buf = ""
    if buf:
        yield start, buf


def check_markdown_hunts(path):
    """KQL / SPL write-ups declare their technique on a '**MITRE ATT&CK:**' line."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r"\*\*MITRE ATT&CK:\*\*(.*)", text)
    if not m:
        err(path, "no '**MITRE ATT&CK:**' line")
        return
    techs = re.findall(r"\[(T\d{4}(?:\.\d{3})?)", m.group(1))
    if not techs:
        err(path, "MITRE ATT&CK line has no technique id")
    if not re.search(r"false.?positive|tuning", text, re.I):
        err(path, "no false-positive / tuning section")
    for t in techs:
        names = coverage.setdefault(t, [])
        if path.stem not in names:
            names.append(path.stem)


def check_suricata(path, seen_sids):
    for n, line in logical_lines(path.read_text(encoding="utf-8")):
        if not line or line.startswith("#"):
            continue
        for field in ("msg", "sid", "rev"):
            if not re.search(rf"\b{field}\s*:", line):
                err(path, f"line {n}: missing '{field}'")
        m = re.search(r"\bsid\s*:\s*(\d+)", line)
        if m:
            if m.group(1) in seen_sids:
                err(path, f"line {n}: duplicate sid {m.group(1)}")
            seen_sids.add(m.group(1))


def main():
    sigma = sorted(SIGMA_DIR.glob("*.yml"))
    suricata = sorted(SURICATA_DIR.glob("*.rules"))
    seen_ids, seen_sids = {}, set()
    for p in sigma:
        check_sigma(p, seen_ids)
    for p in suricata:
        check_suricata(p, seen_sids)
    hunts = sorted((ROOT / "detection-engineering" / "kql-hunts").glob("*.md")) + \
        sorted((ROOT / "detection-engineering" / "splunk-spl").glob("*.md")) + \
        sorted(SURICATA_DIR.glob("*.md"))
    for p in hunts:
        check_markdown_hunts(p)

    print(f"Sigma rules checked:    {len(sigma)}")
    print(f"Suricata files checked: {len(suricata)}")
    print(f"KQL / SPL hunts checked: {len(hunts)}")
    base = {t.split(".")[0] for t in coverage}
    print(f"ATT&CK: {len(base)} techniques ({len(coverage)} counting sub-techniques separately)\n")
    print("| Technique | Rules |")
    print("|---|---|")
    for t in sorted(coverage):
        print(f"| {t} | {'; '.join(coverage[t])} |")
    if errors:
        print(f"\n{len(errors)} problem(s):")
        for e in errors:
            print(f"  ✗ {e}")
        sys.exit(1)
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
