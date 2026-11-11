"""
Pure verdict classification for websocket_security_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.websocket_security_probe.execute import RawHandshakeAttempt, RawWebsocketProbeRun


def _classify(attempt: RawHandshakeAttempt) -> str:
    if attempt.error:
        return "connection_error"
    if not attempt.accepted:
        return "rejected"
    if attempt.origin_label == "same-origin":
        return "accepted_same_origin"
    return "accepted_cross_origin"


def parse(run: RawWebsocketProbeRun) -> Dict[str, Any]:
    if run.error:
        return {"target": run.target, "error": run.error}

    results: List[Dict[str, Any]] = []
    cross_origin_accepted: List[str] = []

    for attempt in run.attempts:
        classification = _classify(attempt)
        if classification == "accepted_cross_origin":
            cross_origin_accepted.append(attempt.origin_label)
        entry: Dict[str, Any] = {
            "origin_label": attempt.origin_label,
            "origin_header": attempt.origin_header,
            "status_line": attempt.status_line,
            "classification": classification,
        }
        if attempt.error:
            entry["error"] = attempt.error
        results.append(entry)

    vulnerable = bool(cross_origin_accepted)
    summary = (
        f"WebSocket handshake accepted (101 Switching Protocols) for cross-origin "
        f"Origin header(s): {', '.join(cross_origin_accepted)} -- missing Origin "
        "validation, a Cross-Site WebSocket Hijacking (CSWSH) risk."
        if vulnerable else
        "No cross-origin Origin value received a 101 Switching Protocols response."
    )

    return {
        "target": run.target,
        "host": run.host,
        "port": run.port,
        "path": run.path,
        "use_tls": run.use_tls,
        "vulnerable": vulnerable,
        "cross_origin_accepted": cross_origin_accepted,
        "summary": summary,
        "attempts": results,
    }
