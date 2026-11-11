"""
Playwright Engine tool: model-directed headless browser interaction.
Glues config/tools/playwright_engine.yaml to tradecraft.adapters.playwright_engine.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.playwright_engine.execute import execute as pw_execute
from tradecraft.adapters.playwright_engine.parse import parse_result as pw_parse_result
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.tools.base import Tool


def parse_host_port_from_url(url: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


class PlaywrightEngine(Tool):
    tool_id = "playwright_engine"

    def __init__(self, store: Optional[EvidenceStore] = None) -> None:
        self._store = store

    def is_available(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def run(
        self,
        target_url: str,
        actions: str = "[]",
        probe_xss: bool = False,
        timeout_seconds: int = 60,
    ) -> Dict[str, Any]:
        try:
            parsed_actions = json.loads(actions) if isinstance(actions, str) else actions
            if not isinstance(parsed_actions, list):
                parsed_actions = []
        except (json.JSONDecodeError, TypeError):
            parsed_actions = []

        raw = pw_execute(
            target_url=target_url,
            actions=parsed_actions,
            probe_xss=probe_xss,
            timeout_seconds=timeout_seconds,
        )
        if raw.error:
            return {"target_url": target_url, "error": raw.error}

        result = pw_parse_result(raw)
        result["target_url"] = target_url

        if raw.screenshot_png:
            store = self._store if self._store is not None else EvidenceStore()
            screenshot_key = store.save_binary(
                target=target_url,
                tool_id=self.tool_id,
                data=raw.screenshot_png,
            )
            result["screenshot_evidence_id"] = screenshot_key
            result["note"] = "screenshot saved to evidence storage; not viewable directly in context"

        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target_url", "")
        if not target:
            return None
        return target, result

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target_url", "")
        host, port = parse_host_port_from_url(target)
        findings = result.get("dom_findings", [])
        if not findings:
            return []
        return [{
            "host": host,
            "port": port,
            "vulnerability": "DOM-based XSS (unescaped reflection confirmed via headless browser)",
            "severity": "high",
            "evidence_id": f"playwright_engine:{host}",
        }]
