"""Pure parsing/shaping for cewl output. No I/O here."""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.cewl.execute import RawCewlResult


def parse_cewl_result(raw: RawCewlResult, target: str) -> Dict[str, Any]:
    if raw.error:
        return {"target": target, "words": [], "total_words": 0, "error": raw.error}
    return {"target": target, "words": raw.words, "total_words": len(raw.words)}
