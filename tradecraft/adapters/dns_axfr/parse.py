"""
Pure parsing of dig AXFR output.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.dns_axfr.execute import RawAxfrResult

_RR_LINE = re.compile(r"^\S+\.?\s+\d+\s+IN\s+\S+", re.MULTILINE)


def parse_one(result: RawAxfrResult) -> Dict[str, Any]:
    """Parses one dig AXFR result against a single nameserver."""
    stdout = result.stdout or ""
    stdout_lower = stdout.lower()

    rejection_markers = [
        "transfer failed",
        "connection refused",
        "communications error",
        "timed out",
        "no servers could be reached",
        "refused",
    ]
    rejected = any(marker in stdout_lower for marker in rejection_markers)

    matched_lines = [
        line.strip()
        for line in stdout.splitlines()
        if _RR_LINE.search(line)
    ]

    vulnerable = bool(matched_lines) and not rejected and not result.error

    sample_records: List[str] = matched_lines[:20]

    return {
        "nameserver": result.nameserver,
        "vulnerable": vulnerable,
        "record_count": len(matched_lines) if vulnerable else 0,
        "sample_records": sample_records if vulnerable else [],
        **({"error": result.error} if result.error else {}),
    }


def parse_all(raw: Dict[str, RawAxfrResult]) -> Dict[str, Any]:
    """Runs parse_one() over every nameserver result."""
    nameservers_tested = list(raw.keys())
    parsed_results = {ns: parse_one(r) for ns, r in raw.items()}
    vulnerable_nameservers = [
        ns for ns, p in parsed_results.items() if p.get("vulnerable")
    ]

    return {
        "nameservers_tested": nameservers_tested,
        "vulnerable_nameservers": vulnerable_nameservers,
        "results": parsed_results,
    }
