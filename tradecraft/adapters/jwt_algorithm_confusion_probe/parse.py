"""
Parsing logic for JWT RS256->HS256 key-confusion differential testing.
Reuses jwt_analyze's own parse_result directly -- the vulnerability
signal (baseline rejected, forged token accepted) is identical
regardless of which forging technique produced the token.
"""
from __future__ import annotations

from tradecraft.adapters.jwt_analyze.parse import parse_result

__all__ = ["parse_result"]
