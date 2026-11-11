"""
Pure classification logic for oauth_redirect_probe. No I/O.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List

from tradecraft.adapters.oauth_redirect_probe.execute import RawOauthRedirectResult, RawRedirectAttempt

_ERROR_MARKERS = ("invalid_request", "invalid redirect", "redirect_uri", "unauthorized_client", "invalid_grant")


def _classify(attempt: RawRedirectAttempt, original: RawRedirectAttempt) -> str:
    if attempt.error:
        return "network_error"

    # Strong positive signal: the IdP immediately redirected toward the
    # attacker-controlled host before any login happened at all.
    mutated_host = urllib.parse.urlsplit(attempt.redirect_uri).hostname or ""
    location_host = urllib.parse.urlsplit(attempt.location).hostname or ""
    if mutated_host and location_host and location_host == mutated_host:
        return "accepted_pre_auth"

    body_lower = (attempt.body or "").lower()
    if attempt.status_code in (400, 401, 403) or any(m in body_lower for m in _ERROR_MARKERS):
        return "rejected"

    # Same shape as the known-good original request -> the IdP is
    # presumably asking for login before it validates redirect_uri at
    # all; this single unauthenticated request can't distinguish
    # "accepted" from "not checked yet".
    if attempt.status_code == original.status_code and abs(len(attempt.body) - len(original.body)) < 200:
        return "inconclusive_requires_login"

    return "inconclusive_requires_login"


def parse(raw: RawOauthRedirectResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    original = RawRedirectAttempt(
        technique="original", redirect_uri=raw.original_redirect_uri,
        status_code=raw.original_status_code, location=raw.original_location,
    )

    results: List[Dict[str, Any]] = []
    accepted: List[str] = []

    for attempt in raw.attempts:
        classification = _classify(attempt, original)
        if classification == "accepted_pre_auth":
            accepted.append(attempt.technique)
        results.append({
            "technique": attempt.technique,
            "redirect_uri": attempt.redirect_uri,
            "status_code": attempt.status_code,
            "location": attempt.location or None,
            "classification": classification,
            "error": attempt.error,
        })

    vulnerable = bool(accepted)
    summary = (
        f"Authorization endpoint redirected directly to the attacker-controlled "
        f"redirect_uri for technique(s): {', '.join(accepted)}, without requiring login."
        if vulnerable else
        "No variant triggered an immediate pre-login redirect to the attacker-controlled "
        "host. A 'rejected' classification means the IdP validated and rejected redirect_uri "
        "up front; 'inconclusive_requires_login' means this IdP only validates redirect_uri "
        "after interactive login, so this single unauthenticated request can't confirm or "
        "rule out the bypass -- a manual check through the full login flow is needed."
    )

    return {
        "target": raw.target,
        "original_redirect_uri": raw.original_redirect_uri,
        "vulnerable": vulnerable,
        "accepted_techniques": accepted,
        "summary": summary,
        "attempts": results,
    }
