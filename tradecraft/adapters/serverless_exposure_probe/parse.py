"""
Pure parsing for serverless_exposure_probe: classifies each checked URL
and sweeps exposed bodies for leaked env-var-shaped secrets. No I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.serverless_exposure_probe.execute import RawFunctionCheck, RawServerlessExposureResult

MAX_SECRET_MATCHES = 10
_SECRET_PATTERNS = (
    re.compile(r"AWS_SECRET_ACCESS_KEY['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+_-]{8,}", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9_]*_KEY['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+_-]{8,}", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9_]*_SECRET['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+_-]{8,}", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9_]*_TOKEN['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+_.-]{8,}", re.IGNORECASE),
    re.compile(r"(mongodb|postgres|mysql|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", re.IGNORECASE),
)

_AUTH_REQUIRED_MARKERS = ("forbidden", "unauthorized", "missing authentication token", "access denied")


def _find_leaked_secrets(body: str) -> List[str]:
    matches: List[str] = []
    for pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(body):
            matches.append(m.group(0)[:200])
            if len(matches) >= MAX_SECRET_MATCHES:
                return matches
    return matches


def _classify(check: RawFunctionCheck) -> str:
    if check.error:
        return "network_error"
    body_lower = (check.body or "").lower()
    if check.status_code == 403 and any(m in body_lower for m in _AUTH_REQUIRED_MARKERS):
        return "exists_auth_required"
    if check.status_code == 404:
        return "not_found"
    if check.status_code == 200:
        return "exposed"
    return "other"


def parse(raw: RawServerlessExposureResult) -> Dict[str, Any]:
    if raw.error:
        return {"provider": raw.provider, "error": raw.error}

    results: List[Dict[str, Any]] = []
    exposed_count = 0
    leaked_secrets_total = 0

    for check in raw.checks:
        classification = _classify(check)
        entry: Dict[str, Any] = {"url": check.url, "status_code": check.status_code, "classification": classification}
        if check.error:
            entry["error"] = check.error
        if classification == "exposed":
            exposed_count += 1
            secrets_found = _find_leaked_secrets(check.body)
            if secrets_found:
                entry["leaked_secrets"] = secrets_found
                leaked_secrets_total += len(secrets_found)
        results.append(entry)

    return {
        "provider": raw.provider,
        "urls_checked": len(raw.checks),
        "exposed_count": exposed_count,
        "leaked_secrets_total": leaked_secrets_total,
        "results": results,
    }
