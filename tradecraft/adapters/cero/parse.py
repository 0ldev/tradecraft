"""
Parsing logic for cero output.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import List


def parse_domains(raw_domains: List[str], target: str) -> List[str]:
    """Cleans, normalizes, and deduplicates domains extracted from cero."""
    seen = set()
    cleaned: List[str] = []

    for d in raw_domains:
        domain = d.strip().lower()
        if not domain:
            continue
        if domain.startswith("*."):
            domain = domain[2:]
        if not domain:
            continue

        if domain not in seen:
            seen.add(domain)
            cleaned.append(domain)

    return sorted(cleaned)
