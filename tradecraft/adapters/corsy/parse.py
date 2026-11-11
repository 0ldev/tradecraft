"""
Pure parsing of corsy output.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


def parse_corsy_output(raw_json: str, default_url: str = "") -> Dict[str, Any]:
    """Parses corsy's JSON output (dict mapping URL to misconfiguration dict)."""
    clean_json = raw_json.strip()
    if not clean_json:
        return {
            "url": default_url,
            "misconfigured": False,
            "findings": [],
        }

    try:
        data = json.loads(clean_json)
    except json.JSONDecodeError:
        return {
            "url": default_url,
            "misconfigured": False,
            "findings": [],
        }

    if not isinstance(data, dict):
        return {
            "url": default_url,
            "misconfigured": False,
            "findings": [],
        }

    findings: List[Dict[str, Any]] = []
    for u, item in data.items():
        if isinstance(item, dict):
            findings.append({
                "url": u,
                "class": item.get("class", ""),
                "description": item.get("description", ""),
                "severity": item.get("severity", ""),
                "exploitation": item.get("exploitation", ""),
                "acao_header": item.get("acao header", ""),
                "acac_header": item.get("acac header", ""),
            })

    return {
        "url": default_url or (findings[0]["url"] if findings else ""),
        "misconfigured": bool(findings),
        "findings": findings,
    }
