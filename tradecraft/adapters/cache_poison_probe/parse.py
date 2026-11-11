"""
Parsing logic for web cache poisoning attempts.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cache_poison_probe.execute import PoisonAttempt

EVIDENCE_SNIPPET_CHARS = 500


def parse_attempt(a: PoisonAttempt) -> Dict[str, Any]:
    """vulnerable = a.attempted_clean and a.marker_value in a.clean_body
    (checked against the FULL body, before truncating for display)."""
    vulnerable = bool(a.attempted_clean and a.marker_value and a.marker_value in a.clean_body)
    res: Dict[str, Any] = {
        "unkeyed_input": a.header_name,
        "vulnerable": vulnerable,
        "poison_status": a.poison_status,
        "clean_status": a.clean_status,
    }
    if vulnerable:
        res["evidence"] = a.clean_body[:EVIDENCE_SNIPPET_CHARS]
        res["marker"] = a.marker_value
    if a.error:
        res["error"] = a.error
    return res


def parse_all(attempts: List[PoisonAttempt]) -> Dict[str, Any]:
    results = [parse_attempt(a) for a in attempts]
    vulnerable_headers = [r["unkeyed_input"] for r in results if r["vulnerable"]]
    return {
        "vulnerable": bool(vulnerable_headers),
        "vulnerable_headers": vulnerable_headers,
        "attempts": results,
    }
