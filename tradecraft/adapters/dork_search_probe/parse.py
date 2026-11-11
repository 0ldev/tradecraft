"""
Pure parsing: RawDorkResult -> structured dict of search hits.
No subprocess, no I/O.
"""
from __future__ import annotations


def parse(raw) -> dict:
    if raw.error:
        return {"query": raw.query, "error": raw.error}
    results = [
        {"title": item.get("title", ""), "url": item.get("link", ""), "snippet": item.get("snippet", "")}
        for item in raw.items
    ]
    return {
        "query": raw.query,
        "result_count": len(results),
        "total_results_reported": raw.total_results_reported,
        "results": results,
        "error": None,
    }
