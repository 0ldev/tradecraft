"""
Pure parsing functions for smuggler output.
Extracts confirmed HTTP request smuggling desync types (CL.TE, TE.CL, TE.TE).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.smuggler.execute import RawSmugglerResult

_DESYNC_TYPES = ["CL.TE", "TE.CL", "TE.TE", "CL.CL"]


def parse_smuggler_output(raw: RawSmugglerResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target_url,
            "vulnerable": False,
            "desync_types": [],
            "findings": [],
            "error": raw.error,
        }

    stdout = f"{raw.stdout}\n{raw.stderr}"
    lines = stdout.splitlines()

    vulnerable = False
    desync_types: List[str] = []
    findings: List[str] = []

    for line in lines:
        cleaned = line.strip()
        lower = cleaned.lower()
        if not cleaned:
            continue

        if "vulnerable" in lower or "critical" in lower or "smuggle" in lower:
            for dtype in _DESYNC_TYPES:
                if dtype.lower() in lower:
                    if dtype not in desync_types:
                        desync_types.append(dtype)
                    vulnerable = True

            if any(term in lower for term in ("potential", "confirmed", "timeout", "status 400", "status 500")):
                findings.append(cleaned)
                vulnerable = True

    return {
        "target": raw.target_url,
        "vulnerable": vulnerable,
        "desync_types": desync_types,
        "findings": findings[:10],
    }
