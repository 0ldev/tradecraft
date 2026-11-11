"""
Tplmap adapter package.
"""
from __future__ import annotations

from tradecraft.adapters.tplmap.execute import RawTplmapResult, execute
from tradecraft.adapters.tplmap.parse import parse_detection

__all__ = ["RawTplmapResult", "execute", "parse_detection"]
