"""
Pure parsing for actuator_probe: splits responding actuator paths into
high-value exposures (direct secret/config/route leaks) and low-value ones.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.actuator_probe.execute import ACTUATOR_PATHS, HIGH_VALUE, PathResult, RawActuatorResult


def _summary(r: PathResult) -> Dict[str, Any]:
    return {"path": r.path, "status": r.status, "content_type": r.content_type}


def parse_actuator_result(raw: RawActuatorResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    hits = [r for r in raw.results if r.looks_like_actuator]
    if not hits:
        return {
            "target": raw.target,
            "reason": (
                f"no actuator path responded as a live endpoint across "
                f"{len(ACTUATOR_PATHS)} candidates"
            ),
        }

    high_value = [r for r in hits if r.path.rsplit("/", 1)[-1] in HIGH_VALUE]
    low_value = [r for r in hits if r not in high_value]
    return {
        "target": raw.target,
        "high_value_exposures": [_summary(r) for r in high_value],
        "low_value_exposures": [_summary(r) for r in low_value],
        "total_hits": len(hits),
    }
