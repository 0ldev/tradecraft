"""
Pure parsing functions for cloudfox output.
Extracts high-value findings, privilege escalation paths, and exposed resources.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.cloudfox.execute import RawCloudfoxResult


def parse_cloudfox_output(raw: RawCloudfoxResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "provider": raw.provider,
            "command": raw.command,
            "findings_count": 0,
            "findings": [],
            "loot": [],
            "error": raw.error,
        }

    findings: List[Dict[str, Any]] = []
    # If structured JSON was captured from output files
    if raw.json_data:
        for item in raw.json_data[:20]:
            findings.append(item)

    # Also parse text output for high-value markers if JSON was empty
    stdout = raw.stdout
    for line in stdout.splitlines():
        cleaned = line.strip()
        lower = cleaned.lower()
        if not cleaned:
            continue
        if any(marker in lower for marker in ("privilege escalation", "admin", "imds", "public", "critical", "high", "loot")):
            if not any(f.get("text") == cleaned for f in findings):
                findings.append({"text": cleaned})

    return {
        "provider": raw.provider,
        "command": raw.command,
        "findings_count": len(findings),
        "findings": findings[:15],
    }
