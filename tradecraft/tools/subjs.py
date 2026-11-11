from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.subjs import execute as subjs_execute
from tradecraft.adapters.subjs import parse as subjs_parse
from tradecraft.tools.base import Tool


def _host_port_from_target(target: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


class Subjs(Tool):
    tool_id = "subjs"

    def run(self, target: str) -> Dict[str, Any]:
        raw = subjs_execute.execute(target)
        if raw.error:
            return {"target": target, "js_urls": [], "error": raw.error}
        if raw.returncode != 0 and not raw.stdout.strip():
            error_msg = raw.stderr.strip() or f"subjs exited with returncode {raw.returncode}"
            return {"target": target, "js_urls": [], "error": error_msg}
        urls = subjs_parse.parse_js_urls(raw.stdout)
        result: Dict[str, Any] = {"target": target, "js_urls": urls}
        if urls:
            result["_full_evidence"] = {"target": target, "js_urls": urls}
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = _host_port_from_target(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        urls = result.get("js_urls", [])
        if not target or not urls:
            return []
        host, port = _host_port_from_target(target)
        fact: Dict[str, Any] = {"host": host, "port": port, "js_urls_discovered": len(urls)}
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
