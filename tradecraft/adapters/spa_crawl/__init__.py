"""
SPA crawl adapter package.
"""
from __future__ import annotations

from tradecraft.adapters.spa_crawl.execute import RawSpaCrawlResult, execute
from tradecraft.adapters.spa_crawl.parse import parse_result

__all__ = ["RawSpaCrawlResult", "execute", "parse_result"]
