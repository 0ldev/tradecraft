"""
Pure parsing functions for coercer scan output.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.coercer.execute import RawCoercerResult

_VULN_METHODS = [
    "MS-EFSR",
    "PetitPotam",
    "MS-RPRN",
    "PrinterBug",
    "MS-DFSNM",
    "ShadowCoerce",
    "MS-FSRVP",
]


def parse_coercer_output(raw: RawCoercerResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "coercible_methods": [],
            "error": raw.error,
        }

    stdout = f"{raw.stdout}\n{raw.stderr}"
    lines = stdout.splitlines()

    vulnerable = False
    coercible_methods: List[str] = []

    for line in lines:
        cleaned = line.strip()
        lower = cleaned.lower()
        if not cleaned:
            continue
        if any(marker in lower for marker in ("vulnerable", "success", "received ntlm", "listening")):
            for m in _VULN_METHODS:
                if m.lower() in lower and m not in coercible_methods:
                    coercible_methods.append(m)
                    vulnerable = True

    return {
        "target": raw.target,
        "vulnerable": vulnerable,
        "coercible_methods": coercible_methods,
        "total_methods": len(coercible_methods),
    }
