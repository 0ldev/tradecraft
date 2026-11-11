"""
Pure parsing for ssrf_probe: flags attempts whose request produced any real
HTTP response from the injected internal address. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.ssrf_probe.execute import RawSsrfResult, SsrfAttempt


def _likely_reached(a: SsrfAttempt) -> bool:
    # A connection error means the request almost certainly did not reach
    # anything internal. Any real HTTP response (even 400/401/403) means the
    # request reached some server at the injected address.
    return a.status is not None and a.status != 404 and (a.status < 500 or a.status in (400, 401, 403))


def parse_ssrf_result(raw: RawSsrfResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    hits = [a for a in raw.attempts if _likely_reached(a)]
    if not hits:
        return {
            "target": raw.target,
            "inject_location": raw.inject_location,
            "reason": f"no injected internal URL produced a response across {len(raw.attempts)} attempt(s)",
        }

    result: Dict[str, Any] = {
        "target": raw.target,
        "inject_location": raw.inject_location,
        "hits": [
            {
                "preset_label": a.preset_label,
                "internal_url": a.internal_url,
                "status": a.status,
                "body_snippet": a.body_snippet,
            }
            for a in hits
        ],
    }
    if any(a.preset_label == "oob_blind" for a in raw.attempts):
        result["oob_pending"] = True
    return result
