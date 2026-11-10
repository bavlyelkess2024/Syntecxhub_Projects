"""Report generation (Markdown / JSON)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List

DISCLOSURE_NOTES = """\
## Triage & responsible disclosure basics

1. **Triage** each finding by severity (CVSS), exposure and whether the detected
   version really matches (banners can be wrong or backported).
2. **Verify safely** - confirm without exploiting, disrupting or accessing data.
3. **Report privately** to the system owner / vendor (security contact,
   `security.txt`, bug-bounty program) with evidence and remediation advice.
4. **Allow time to fix** (commonly 90 days) before any public disclosure.
5. **Remediate**: patch or upgrade, restrict exposure, hide version banners.
"""


def summarize(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        for c in f["cves"]:
            counts[c["severity"]] = counts.get(c["severity"], 0) + 1
    return counts


def to_markdown(host: str, findings: List[Dict]) -> str:
    lines = [f"# CVE Scan Report - {host}",
             f"_Generated: {datetime.now():%Y-%m-%d %H:%M}_", "",
             "> Matches are candidates based on banners/keywords and may include "
             "false positives. Verify manually.", "",
             "## Summary", ""]
    counts = summarize(findings)
    lines.append(", ".join(f"**{k}**: {v}" for k, v in counts.items())
                 if counts else "No CVE matches found.")
    lines += ["", "| Port | Service | Version | CVEs |", "|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f['port']} | {f['product'] or '?'} | "
                     f"{f['version'] or '?'} | {len(f['cves'])} |")
    lines.append("")
    for f in findings:
        if not f["cves"]:
            continue
        lines.append(f"## Port {f['port']} - {f['product']} {f['version']}")
        for c in f["cves"]:
            score = c["score"] if c["score"] is not None else "n/a"
            lines.append(f"- **{c['id']}** [{c['severity']} / {score}] - {c['description']}")
        lines.append("")
    lines.append(DISCLOSURE_NOTES)
    return "\n".join(lines)


def to_json(host: str, findings: List[Dict]) -> str:
    return json.dumps({"host": host, "generated": datetime.now().isoformat(),
                       "findings": findings}, indent=2)
