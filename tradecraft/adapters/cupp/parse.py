"""Pure parsing/shaping for cupp output. No I/O here."""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.cupp.execute import RawCuppResult


def parse_cupp_result(raw: RawCuppResult) -> Dict[str, Any]:
    if raw.error:
        return {"words": [], "total_words": 0, "error": raw.error}
    return {"words": raw.words, "total_words": len(raw.words)}
