"""
Pure parsing/verdict logic for price_manipulation_probe. No I/O. Same
classification shape as mass_assignment_probe's own _classify.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from tradecraft.adapters.price_manipulation_probe.execute import RawPriceManipulationResult


def _classify(attempt_status: int, body: str, param: str, injected_value: object) -> str:
    if attempt_status == 0:
        return "network_error"
    if attempt_status in (401, 403):
        return "rejected_auth"
    if attempt_status in (400, 404, 405, 409, 422):
        return "rejected_validation"
    if attempt_status >= 500:
        return "server_error"
    if attempt_status not in range(200, 300):
        return "unclassified"

    try:
        data = json.loads(body)
    except Exception:
        return "accepted_unconfirmed"

    if isinstance(data, dict) and param in data and data[param] == injected_value:
        return "accepted_confirmed"
    return "accepted_unconfirmed"


def parse(raw: RawPriceManipulationResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    results: List[Dict[str, Any]] = []
    confirmed = 0
    unconfirmed = 0

    for attempt in raw.attempts:
        if attempt.error:
            results.append({
                "variant": attempt.variant, "param": attempt.param, "injected_value": attempt.injected_value,
                "classification": "network_error", "error": attempt.error,
            })
            continue

        classification = _classify(attempt.status_code, attempt.body, attempt.param, attempt.injected_value)
        if classification == "accepted_confirmed":
            confirmed += 1
        elif classification == "accepted_unconfirmed":
            unconfirmed += 1

        results.append({
            "variant": attempt.variant,
            "param": attempt.param,
            "injected_value": attempt.injected_value,
            "status_code": attempt.status_code,
            "classification": classification,
            "response_snippet": attempt.body[:500],
        })

    summary = (
        f"Tested {len(raw.attempts)} tamper variant(s) via {raw.method}. "
        f"{confirmed} confirmed accepted (echoed back with the tampered value), "
        f"{unconfirmed} accepted but unconfirmed (2xx response, field not echoed -- "
        "verify persistence with a follow-up read)."
    )

    return {
        "target": raw.target,
        "method": raw.method,
        "baseline_body": raw.baseline_body,
        "variants_tested": len(raw.attempts),
        "confirmed_accepted": confirmed,
        "unconfirmed_accepted": unconfirmed,
        "summary": summary,
        "attempts": results,
    }
