"""
Pure parsing functions for ghauri output.
Extracts confirmed injectable parameters, techniques, and backend DBMS.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.ghauri.execute import RawGhauriResult

_TECHNIQUES = [
    "boolean-based blind",
    "error-based",
    "time-based blind",
    "stacked queries",
    "inline queries",
]


def parse_ghauri_output(raw: RawGhauriResult) -> Dict[str, Any]:
    """Parses ghauri stdout into confirmed SQL injection facts."""
    if raw.error:
        return {
            "target": raw.target_url,
            "parameter": raw.parameter,
            "vulnerable": False,
            "dbms": "",
            "techniques": [],
            "current_user": "",
            "error": raw.error,
        }

    stdout = raw.stdout
    lower = stdout.lower()

    vulnerable = False
    dbms = ""
    current_user = ""
    techniques: List[str] = []

    # Look for parameter confirmation
    if "is vulnerable" in lower or "parameter appears to be dynamic" in lower:
        vulnerable = True

    for tech in _TECHNIQUES:
        if tech in lower:
            techniques.append(tech)
            vulnerable = True

    dbms_match = re.search(r"back-end DBMS:\s*([^\r\n]+)", stdout, re.IGNORECASE)
    if dbms_match:
        dbms = dbms_match.group(1).strip()
        vulnerable = True

    user_match = re.search(r"current user:\s*['\"]?([^'\"\r\n]+)['\"]?", stdout, re.IGNORECASE)
    if user_match:
        current_user = user_match.group(1).strip()

    return {
        "target": raw.target_url,
        "parameter": raw.parameter,
        "vulnerable": vulnerable,
        "dbms": dbms,
        "techniques": techniques,
        "current_user": current_user,
    }
