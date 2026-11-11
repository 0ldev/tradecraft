"""
Parsing LinkFinder CLI output into a clean list of candidate endpoints.
Pure functions, no I/O.
"""
from __future__ import annotations

import html
from typing import List


def parse_endpoints(stdout: str) -> List[str]:
    """Extract path- and URL-shaped strings from LinkFinder CLI output."""
    if not stdout or not stdout.strip():
        return []

    endpoints: List[str] = []
    seen: set[str] = set()

    for line in stdout.splitlines():
        clean = line.strip()
        if not clean:
            continue
        if clean.startswith("/") or clean.startswith("http"):
            unescaped = html.unescape(clean)
            if unescaped not in seen:
                seen.add(unescaped)
                endpoints.append(unescaped)

    return sorted(endpoints)
