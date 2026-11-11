"""
Pure parsing for xxe_probe. This tool never claims an XXE hit itself: a
callback can only be confirmed by polling interactsh, so the report always
carries the status, the snippet, and a note to poll. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.xxe_probe.execute import RawXxeResult

POLL_NOTE = "poll interactsh separately and match any callback to this oob_domain"


def parse_xxe_result(raw: RawXxeResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}
    return {
        "target": raw.target,
        "oob_domain": raw.oob_domain,
        "status": raw.status,
        "body_snippet": raw.body_snippet,
        "note": POLL_NOTE,
    }
