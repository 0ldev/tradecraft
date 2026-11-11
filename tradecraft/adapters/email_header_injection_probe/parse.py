"""
Pure classification logic for email_header_injection_probe. No I/O.
Same shape as csrf_probe's own _classify -- "accepted" here means the
injected header was not rejected, not that delivery was confirmed.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.email_header_injection_probe.execute import (
    RawEmailHeaderInjectionAttempt,
    RawEmailHeaderInjectionResult,
)

_REJECTION_STATUS = (400, 401, 403, 422)


def _classify(attempt: RawEmailHeaderInjectionAttempt) -> str:
    if attempt.error:
        return "network_error"
    if attempt.status_code in _REJECTION_STATUS:
        return "rejected"
    if attempt.status_code in range(300, 400):
        return "redirected"
    if attempt.status_code in range(200, 300):
        return "accepted"
    return "unclassified"


def parse(raw: RawEmailHeaderInjectionResult) -> Dict[str, Any]:
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
        f"Endpoint accepted the injected Bcc header via: {', '.join(accepted_variants)} -- "
        "confirms only that the header was not rejected; check the marker mailbox "
        f"({raw.bcc_marker}) separately (e.g. with mail_access_probe) to confirm actual delivery."
        if vulnerable else
        f"Both gated attempts ({', '.join(a.variant for a in raw.attempts)}) were rejected or redirected -- "
        "no evidence of header injection."
    )

    return {
        "target": raw.target,
        "method": raw.method,
        "field_to_inject": raw.field_to_inject,
        "bcc_marker": raw.bcc_marker,
        "vulnerable": vulnerable,
        "accepted_variants": accepted_variants,
        "summary": summary,
        "attempts": results,
    }
