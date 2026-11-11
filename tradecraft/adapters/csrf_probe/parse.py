"""
Pure classification logic for csrf_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.csrf_probe.execute import RawCsrfAttempt, RawCsrfProbeResult

_REJECTION_STATUS = (400, 401, 403, 419, 422)


def _classify(attempt: RawCsrfAttempt) -> str:
    if attempt.error:
        return "network_error"
    if attempt.status_code in _REJECTION_STATUS:
        return "rejected"
    if attempt.status_code in range(300, 400):
        return "redirected"  # commonly a redirect to an error page; ambiguous without more context
    if attempt.status_code in range(200, 300):
        return "accepted"
    return "unclassified"


def parse(raw: RawCsrfProbeResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    results: List[Dict[str, Any]] = []
    accepted_variants: List[str] = []

    for attempt in raw.attempts:
        classification = _classify(attempt)
        if classification == "accepted":
            accepted_variants.append(attempt.variant)
        results.append({
            "variant": attempt.variant,
            "status_code": attempt.status_code,
            "classification": classification,
            "error": attempt.error,
        })

    vulnerable = bool(accepted_variants)
    summary = (
        f"Endpoint still accepted the request with: {', '.join(accepted_variants)} -- "
        "CSRF token is not actually validated server-side."
        if vulnerable else
        f"Both gated attempts ({', '.join(a.variant for a in raw.attempts)}) were rejected or redirected -- "
        "no evidence of missing CSRF validation."
    )

    return {
        "target": raw.target,
        "method": raw.method,
        "vulnerable": vulnerable,
        "accepted_variants": accepted_variants,
        "summary": summary,
        "attempts": results,
    }
