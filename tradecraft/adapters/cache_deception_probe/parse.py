"""
Parsing logic for web cache deception attempts.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cache_deception_probe.execute import DeceptionAttempt


def _attempt_summary(a: DeceptionAttempt) -> Dict[str, Any]:
    # Bodies are deliberately omitted: full bodies belong only in the tool
    # layer's _full_evidence, not in the model-facing summary.
    return {
        "suffix": a.suffix,
        "crafted_url": a.crafted_url,
        "authed_status": a.authed_status,
        "authed_marker_found": a.authed_marker_found,
        "clean_status": a.clean_status,
        "clean_marker_found": a.clean_marker_found,
        "deception_confirmed": a.deception_confirmed,
        "error": a.error,
    }


def parse(attempts: List[DeceptionAttempt]) -> Dict[str, Any]:
    # Early-exit shape from execute(): a single error-only entry with no suffix
    # (empty target or missing requests library).
    if len(attempts) == 1 and attempts[0].error and not attempts[0].suffix:
        return {"error": attempts[0].error}

    confirmed = [a.suffix for a in attempts if a.deception_confirmed]
    return {
        "confirmed_suffixes": confirmed,
        "vulnerable": len(confirmed) > 0,
        "tested_suffixes": [a.suffix for a in attempts],
        "attempts": [_attempt_summary(a) for a in attempts],
    }
