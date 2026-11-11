"""
Pure shaping for subdomain_permute: dedupes and sorts the generated names and
builds the report the model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.subdomain_permute.execute import RawPermuteResult


def parse_permute_result(raw: RawPermuteResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}
    candidates = sorted(set(raw.candidates))
    return {
        "target": raw.target,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
