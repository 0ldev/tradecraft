"""
Pure parsing functions for kerbrute_spray output.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.kerbrute_spray.execute import RawKerbruteSprayResult

_VALID_CRED_REGEX = re.compile(r"\[\+\]\s+VALID LOGIN:\s+([^\s]+)", re.IGNORECASE)


def parse_kerbrute_spray_output(raw: RawKerbruteSprayResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "domain": raw.domain,
            "password": "<redacted>",
            "valid_credentials": [],
            "total_valid": 0,
            "error": raw.error,
        }

    stdout = raw.stdout
    valid_creds: List[str] = []

    for match in _VALID_CRED_REGEX.finditer(stdout):
        user_part = match.group(1).strip()
        if user_part and user_part not in valid_creds:
            valid_creds.append(user_part)

    return {
        "domain": raw.domain,
        "valid_credentials": valid_creds,
        "total_valid": len(valid_creds),
    }
