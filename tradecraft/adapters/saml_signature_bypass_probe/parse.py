"""
Pure verdict classification for saml_signature_bypass_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.saml_signature_bypass_probe.execute import RawSamlAttempt, RawSamlBypassResult

_ERROR_MARKERS = ("invalid signature", "signature validation failed", "invalid saml", "unauthorized", "invalid_response")


def _classify(attempt: RawSamlAttempt) -> str:
    if attempt.mutation_error:
        return "mutation_not_applicable"
    if attempt.error:
        return "network_error"

    body_lower = (attempt.body or "").lower()
    if any(m in body_lower for m in _ERROR_MARKERS):
        return "rejected"

    # A session cookie or a redirect toward an authenticated area, with no
    # explicit rejection message, is treated as the SP accepting the
    # mutated assertion.
    if attempt.set_cookie or attempt.status_code in (302, 303):
        return "accepted"
    if attempt.status_code in (400, 401, 403):
        return "rejected"
    return "inconclusive"


def parse(raw: RawSamlBypassResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    results: List[Dict[str, Any]] = []
    accepted_mutations: List[str] = []

    for attempt in raw.attempts:
        classification = _classify(attempt)
        if classification == "accepted":
            accepted_mutations.append(attempt.mutation)
        entry: Dict[str, Any] = {
            "mutation": attempt.mutation,
            "status_code": attempt.status_code,
            "classification": classification,
        }
        if attempt.mutation_error:
            entry["mutation_error"] = attempt.mutation_error
        if attempt.error:
            entry["error"] = attempt.error
        results.append(entry)

    vulnerable = bool(accepted_mutations)
    summary = (
        f"SP accepted the mutated SAMLResponse for: {', '.join(accepted_mutations)} -- "
        "signature validation is bypassable, a full SSO authentication bypass."
        if vulnerable else
        "No mutation was accepted by the SP as a valid authenticated session."
    )

    return {
        "target": raw.target,
        "vulnerable": vulnerable,
        "accepted_mutations": accepted_mutations,
        "summary": summary,
        "attempts": results,
    }
