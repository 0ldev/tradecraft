"""
SpaCrawl tool: automated generic SPA interaction discovery.
Glues config/tools/spa_crawl.yaml to tradecraft.adapters.spa_crawl.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.spa_crawl.execute import execute as spa_execute
from tradecraft.adapters.spa_crawl.parse import parse_result as spa_parse_result
from tradecraft.tools.base import Tool


class SpaCrawl(Tool):
    tool_id = "spa_crawl"

    def is_available(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target_url: str, timeout_seconds: int = 45) -> Dict[str, Any]:
        raw = spa_execute(target_url=target_url, timeout_seconds=timeout_seconds)
        if raw.error:
            return {"target": target_url, "target_url": target_url, "error": raw.error}
        result = spa_parse_result(raw)
        result["target"] = target_url
        result["target_url"] = target_url
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target_url") or params.get("target") or result.get("target_url", "")
        if not target:
            return None
        return target, result

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Discovered request shapes aren't vulnerabilities by themselves.
        # No deterministic facts to extract; the model logs findings or notes.
        return []
