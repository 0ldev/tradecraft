"""
Parsing logic for tplmap / sstimap detection output.
Pure functions, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
INJECTION_POINT_RE = re.compile(r"identified the following injection point", re.IGNORECASE)
CONFIRMED_INJECTION_RE = re.compile(r"\[\+\]\s*(\w+)\s+plugin has confirmed injection", re.IGNORECASE)
ENGINE_RE = re.compile(r"^\s*Engine:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
PARAM_RE = re.compile(r"^\s*(?:Query|Body|Header|Cookie)?\s*parameter:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
TECHNIQUE_RE = re.compile(r"^\s*Technique:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def parse_detection(stdout: str) -> Dict[str, Any]:
    """Parses SSTI detection output from tplmap or sstimap."""
    if not stdout:
        return {"vulnerable": False, "raw_output": ""}

    clean_stdout = ANSI_ESCAPE_RE.sub("", stdout).strip()

    is_vuln = bool(
        INJECTION_POINT_RE.search(clean_stdout)
        or CONFIRMED_INJECTION_RE.search(clean_stdout)
    )

    result: Dict[str, Any] = {
        "vulnerable": is_vuln,
        "raw_output": clean_stdout[:2000],
    }

    if is_vuln:
        engine_match = ENGINE_RE.search(clean_stdout)
        if engine_match:
            result["engine"] = engine_match.group(1).strip()
        else:
            plugin_match = CONFIRMED_INJECTION_RE.search(clean_stdout)
            if plugin_match:
                result["engine"] = plugin_match.group(1).strip()

        param_match = PARAM_RE.search(clean_stdout)
        if param_match:
            result["parameter"] = param_match.group(1).strip()

        tech_match = TECHNIQUE_RE.search(clean_stdout)
        if tech_match:
            result["technique"] = tech_match.group(1).strip()

    return result
