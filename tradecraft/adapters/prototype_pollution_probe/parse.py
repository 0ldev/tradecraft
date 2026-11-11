"""
Pure classification logic for prototype_pollution_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.prototype_pollution_probe.execute import RawPollutionAttempt, RawPrototypePollutionResult


def _reflected(attempt: RawPollutionAttempt, marker_value: str) -> bool:
    return marker_value in (attempt.body or "")


def parse(raw: RawPrototypePollutionResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    results: List[Dict[str, Any]] = []
    reflected_vectors: List[str] = []

    for attempt in raw.attempts:
        if attempt.error:
            results.append({"vector": attempt.vector, "classification": "network_error", "error": attempt.error})
            continue
        reflected = _reflected(attempt, raw.marker_value)
        if reflected:
            reflected_vectors.append(attempt.vector)
        results.append({
            "vector": attempt.vector,
            "status_code": attempt.status_code,
            "reflected_in_response": reflected,
        })

    leaked_cross_endpoint = False
    verify_note = None
    if raw.verify_error:
        verify_note = f"verify_url check failed: {raw.verify_error}"
    elif raw.verify_status_code is not None:
        leaked_cross_endpoint = raw.marker_value in (raw.verify_body or "")

    vulnerable = bool(reflected_vectors) or leaked_cross_endpoint
    summary_parts = []
    if reflected_vectors:
        summary_parts.append(f"marker property reflected directly via: {', '.join(reflected_vectors)}")
    if leaked_cross_endpoint:
        summary_parts.append("marker also leaked into verify_url's separate response (global pollution confirmed)")
    if not summary_parts:
        summary_parts.append("no marker reflection observed in this response or in verify_url")
    summary = "; ".join(summary_parts) + ". Observational only -- no persistent storage was targeted."

    out: Dict[str, Any] = {
        "target": raw.target,
        "marker_property": raw.marker_property,
        "vulnerable": vulnerable,
        "reflected_vectors": reflected_vectors,
        "leaked_cross_endpoint": leaked_cross_endpoint,
        "summary": summary,
        "attempts": results,
    }
    if verify_note:
        out["verify_note"] = verify_note
    return out
