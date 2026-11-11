"""
Pure parsing for hpp_probe: classifies each duplicate-parameter attempt
from the raw response evidence. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.hpp_probe.execute import RawHppAttempt, RawHppResult


def _classify(attempt: RawHppAttempt) -> str:
    if attempt.error:
        return "network_error"
    if attempt.sentinel_reflected:
        return "sentinel_reflected"
    if attempt.response_changed:
        return "response_changed"
    return "no_change"


def parse(raw: RawHppResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "method": raw.method, "error": raw.error}

    entries: List[Dict[str, Any]] = []
    observed = False
    for attempt in raw.attempts:
        classification = _classify(attempt)
        if classification in ("sentinel_reflected", "response_changed"):
            observed = True
        entry: Dict[str, Any] = {
            "param": attempt.param,
            "location": attempt.location,
            "ordering": attempt.ordering,
            "status_code": attempt.status_code,
            "body_length": attempt.body_length,
            "classification": classification,
        }
        if classification == "sentinel_reflected":
            entry["value_used"] = "first" if attempt.ordering == "sentinel_then_original" else "last"
        if attempt.error:
            entry["error"] = attempt.error
        entries.append(entry)

    summary = (
        "Duplicate parameters changed server-side handling; review the per-attempt classification."
        if observed
        else "No duplicate-parameter variant changed the response relative to the baseline."
    )
    if raw.skipped_params:
        summary += f" Not present in the request (skipped): {', '.join(raw.skipped_params)}."

    return {
        "target": raw.target,
        "method": raw.method,
        "params_tested": raw.param_names,
        "skipped_params": raw.skipped_params,
        "baseline_status": raw.baseline_status,
        "baseline_length": raw.baseline_length,
        "hpp_observed": observed,
        "attempts": entries,
        "summary": summary,
    }
