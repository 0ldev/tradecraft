"""
Parsing logic for spa_crawl output.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.spa_crawl.execute import RawSpaCrawlResult


def parse_result(raw: RawSpaCrawlResult) -> Dict[str, Any]:
    """Formats RawSpaCrawlResult into a dictionary for the model context."""
    output: Dict[str, Any] = {
        "final_url": raw.final_url,
        "requests": raw.requests,
        "total_requests": len(raw.requests),
    }
    if raw.error:
        output["error"] = raw.error
    return output
