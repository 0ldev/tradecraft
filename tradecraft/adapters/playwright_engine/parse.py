"""
Parsing logic for playwright_engine output.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.playwright_engine.execute import RawPlaywrightResult


def parse_result(raw: RawPlaywrightResult) -> Dict[str, Any]:
    """Formats RawPlaywrightResult into dictionary for model context."""
    output: Dict[str, Any] = {
        "final_url": raw.final_url,
        "dom_findings": raw.dom_findings,
        "storage_keys": raw.storage_keys,
        "requests": raw.requests,
    }
    if raw.error:
        output["error"] = raw.error
    return output
