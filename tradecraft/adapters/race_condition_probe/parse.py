"""
Pure parsing for race_condition_probe. Shapes the raw burst result into the
model-facing summary. body_snippet is deliberately left out here -- the full
per-attempt detail is carried only by the tool layer's _full_evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List

MAX_MODEL_ATTEMPTS = 10


def parse(raw) -> dict:
    attempts_all: List[Dict[str, Any]] = [
        {
            "index": a.index,
            "status_code": a.status_code,
            "success_marker_found": a.success_marker_found,
            "duration_seconds": a.duration_seconds,
            "error": a.error,
        }
        for a in raw.attempts
    ]

    parsed: Dict[str, Any] = {
        "url": raw.url,
        "method": raw.method,
        "requested_count": raw.requested_count,
        "success_count": raw.success_count,
        "likely_race_condition": raw.likely_race_condition,
        "error": raw.error,
        "attempts": attempts_all[:MAX_MODEL_ATTEMPTS],
    }

    if len(attempts_all) > MAX_MODEL_ATTEMPTS:
        omitted = len(attempts_all) - MAX_MODEL_ATTEMPTS
        parsed["omitted_attempts"] = omitted
        parsed["note"] = (
            f"{omitted} more attempts omitted to conserve context. "
            "Use read_evidence to inspect all."
        )

    return parsed
