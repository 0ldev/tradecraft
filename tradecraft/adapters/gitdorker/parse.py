"""
Pure parsing: GitDorker CSV rows -> structured list of GitHub finding dicts.
No subprocess, no I/O.
"""
from __future__ import annotations

from typing import Dict, List

SECRET_MARKERS = ("password", "secret", "token", "api_key", "apikey", "private_key")


def parse_findings(csv_rows: List[List[str]]) -> List[Dict[str, str]]:
    """Parse GitDorker CSV output into deduplicated finding dicts.

    Filters out empty rows and header/junk rows whose first column does not start
    with 'http'. Deduplicates by URL (first-seen wins).
    """
    findings: List[Dict[str, str]] = []
    seen_urls = set()

    for row in csv_rows:
        if not row:
            continue

        raw_url = row[0].strip()
        if not raw_url.lower().startswith("http"):
            continue

        if raw_url in seen_urls:
            continue
        seen_urls.add(raw_url)

        dork = row[1].strip() if len(row) > 1 else ""
        dork_lower = dork.lower()

        finding_type = (
            "secret"
            if any(marker in dork_lower for marker in SECRET_MARKERS)
            else "repo"
        )

        findings.append({
            "type": finding_type,
            "url": raw_url,
            "dork": dork,
        })

    return findings
