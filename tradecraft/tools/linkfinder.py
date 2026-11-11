from __future__ import annotations

import shutil
import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.linkfinder import execute as linkfinder_execute
from tradecraft.adapters.linkfinder import parse as linkfinder_parse
from tradecraft.tools.base import Tool


class LinkFinder(Tool):
    tool_id = "linkfinder"

    def is_available(self) -> bool:
        return shutil.which("python3") is not None and linkfinder_execute.find_script() is not None

    def run(self, target: str) -> Dict[str, Any]:
        raw = linkfinder_execute.execute(target)
        if raw.error:
            return {"target": target, "endpoints_discovered": [], "error": raw.error}

        endpoints = linkfinder_parse.parse_endpoints(raw.stdout)
        res: Dict[str, Any] = {
            "target": target,
            "endpoints_discovered": endpoints[:30],
        }
        if len(endpoints) > 30:
            res["omitted_endpoints"] = len(endpoints) - 30
            res["note"] = f"{len(endpoints) - 30} more omitted -- use read_evidence to inspect all."

        res["_full_evidence"] = {
            "target": target,
            "endpoints_discovered": endpoints,
            "raw_output": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        endpoints = result.get("endpoints_discovered", [])
        if not target or not endpoints:
            return []

        parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        total = result.get("omitted_endpoints", 0) + len(endpoints)

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "js_endpoints_found": total,
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
