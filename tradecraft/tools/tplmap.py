"""
Tplmap tool: Server-Side Template Injection (SSTI) detection.
Glues config/tools/tplmap.yaml to tradecraft.adapters.tplmap.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.tplmap.execute import execute as tplmap_execute
from tradecraft.adapters.tplmap.execute import find_script as tplmap_find_script
from tradecraft.adapters.tplmap.parse import parse_detection as tplmap_parse_detection
from tradecraft.tools.base import Tool


def parse_host_port_from_url(url: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


class Tplmap(Tool):
    tool_id = "tplmap"

    def is_available(self) -> bool:
        if not super().is_available():
            return False
        return bool(tplmap_find_script())

    def run(self, target_url: str) -> Dict[str, Any]:
        raw = tplmap_execute(target_url=target_url)
        if raw.error:
            return {
                "target": target_url,
                "target_url": target_url,
                "error": raw.error,
            }
        parsed = tplmap_parse_detection(raw.stdout)
        parsed["target"] = target_url
        parsed["target_url"] = target_url
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target_url") or result.get("target_url")
        if not target:
            return None
        return target, result

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        target = params.get("target_url", "")
        host, port = parse_host_port_from_url(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": "Server-Side Template Injection (SSTI)",
            "severity": "high",
        }
        if result.get("engine"):
            fact["template_engine"] = result["engine"]
        return [fact]
