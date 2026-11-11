"""
Pure parsing: subzy's stdout -> structured list of vulnerable subdomains.
No subprocess, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

_VULN_PATTERN = re.compile(
    r"\[\s*VULNERABLE\s*\]\s*-\s*([a-zA-Z0-9.\-_]+)(?:\s*\[\s*([^\]]+)\s*\])?",
    re.IGNORECASE,
)
_DOC_PATTERN = re.compile(r"\[\s*DOCUMENTATION\s*\]\s*-\s*(.+)", re.IGNORECASE)
_DISC_PATTERN = re.compile(r"\[\s*DISCUSSION\s*\]\s*-\s*(.+)", re.IGNORECASE)


def parse_subzy_output(stdout: str) -> List[Dict[str, Any]]:
    """Parse subzy CLI output and extract confirmed takeover vulnerabilities.

    Guards against false positives by explicitly ignoring any line matching
    'NOT VULNERABLE'.
    """
    if not stdout or not stdout.strip():
        return []

    findings: List[Dict[str, Any]] = []
    current_finding: Dict[str, Any] | None = None

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Critical guard: never match a negative result
        if "NOT VULNERABLE" in line:
            continue

        vuln_match = _VULN_PATTERN.search(line)
        if vuln_match:
            subdomain = vuln_match.group(1).strip()
            service = (vuln_match.group(2) or "").strip()
            current_finding = {
                "subdomain": subdomain,
                "service": service or "Unknown",
                "status": "vulnerable",
            }
            findings.append(current_finding)
            continue

        if current_finding is not None:
            doc_match = _DOC_PATTERN.search(line)
            if doc_match:
                current_finding["documentation"] = doc_match.group(1).strip()
                continue

            disc_match = _DISC_PATTERN.search(line)
            if disc_match:
                current_finding["discussion"] = disc_match.group(1).strip()
                continue

    return findings
