"""
Pure parsing for api_version_shadow_probe: decides which version variants
answered without credentials. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.api_version_shadow_probe.execute import RawApiVersionShadowResult


def parse(raw: RawApiVersionShadowResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    if raw.baseline_already_open:
        return {
            "target": raw.target,
            "method": raw.method,
            "baseline_status": raw.baseline_status,
            "vulnerable": False,
            "reason": (
                f"baseline answered {raw.baseline_status} unauthenticated -- "
                "the supplied endpoint is not auth-protected, so there is no shadow-version comparison to make"
            ),
            "variants": [],
        }

    if not raw.baseline_was_blocked:
        return {
            "target": raw.target,
            "method": raw.method,
            "baseline_status": raw.baseline_status,
            "vulnerable": False,
            "reason": f"baseline was not 401/403 ({raw.baseline_status}); no auth boundary to bypass",
            "variants": [],
        }

    accessible = [
        v
        for v in raw.variants
        if v.error is None
        and v.status is not None
        and 200 <= v.status < 300
        and v.body_length != raw.baseline_length
    ]
    entries = [
        {
            "label": v.label,
            "url": v.url,
            "status": v.status,
            "body_length": v.body_length,
        }
        for v in raw.variants
    ]
    if not accessible:
        return {
            "target": raw.target,
            "method": raw.method,
            "baseline_status": raw.baseline_status,
            "baseline_length": raw.baseline_length,
            "vulnerable": False,
            "reason": "no alternate version prefix answered 2xx unauthenticated",
            "variants": entries,
        }

    return {
        "target": raw.target,
        "method": raw.method,
        "baseline_status": raw.baseline_status,
        "baseline_length": raw.baseline_length,
        "vulnerable": True,
        "accessible_variants": [
            {
                "label": v.label,
                "url": v.url,
                "status": v.status,
                "body_length": v.body_length,
            }
            for v in accessible
        ],
        "variants_tested": len(raw.variants),
        "variants": entries,
    }
