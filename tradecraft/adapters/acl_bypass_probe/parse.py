"""
Pure parsing for acl_bypass_probe: decides which variant responses flipped a
401/403 block into something else. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.acl_bypass_probe.execute import BLOCKED_STATUSES, RawAclBypassResult

MAX_REPORTED_BYPASSES = 10


def parse_acl_bypass_result(raw: RawAclBypassResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    if not raw.baseline_was_blocked:
        return {
            "target": raw.target,
            "baseline_status": raw.baseline_status,
            "reason": f"baseline was not 401/403 ({raw.baseline_status}); nothing to bypass",
        }

    bypasses = [
        a
        for a in raw.attempts
        if a.error is None
        and a.status not in BLOCKED_STATUSES
        and a.body_length != raw.baseline_length
    ]
    if not bypasses:
        return {
            "target": raw.target,
            "baseline_status": raw.baseline_status,
            "reason": "no variant bypassed the block",
        }

    entries = [
        {
            "label": a.label,
            "url_or_header": (
                f"{a.extra_header[0]}: {a.extra_header[1]}" if a.extra_header else a.url
            ),
            "status": a.status,
            "body_length": a.body_length,
        }
        for a in bypasses[:MAX_REPORTED_BYPASSES]
    ]
    result: Dict[str, Any] = {
        "target": raw.target,
        "baseline_status": raw.baseline_status,
        "baseline_length": raw.baseline_length,
        "bypasses": entries,
    }
    if len(bypasses) > MAX_REPORTED_BYPASSES:
        result["truncated"] = True
    return result
