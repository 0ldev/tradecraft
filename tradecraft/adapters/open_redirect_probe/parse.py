"""
Pure parsing for open_redirect_probe: picks out payloads whose response
redirected to the canary host. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.open_redirect_probe.execute import RawOpenRedirectResult


def parse_open_redirect_result(raw: RawOpenRedirectResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    hits = [a for a in raw.attempts if a.redirects_to_canary]
    if not hits:
        return {
            "target": raw.target,
            "reason": (
                f"no payload produced a redirect to the canary host across "
                f"{len(raw.tested_params)} parameter(s) tested"
            ),
        }

    return {
        "target": raw.target,
        "tested_params": raw.tested_params,
        "vulnerable_params": sorted({a.param for a in hits}),
        "hits": [
            {
                "param": a.param,
                "payload_label": a.payload_label,
                "payload": a.payload,
                "status": a.status,
                "location": a.location,
            }
            for a in hits
        ],
    }
