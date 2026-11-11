from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.wafw00f import execute as wafw00f_execute
from tradecraft.adapters.wafw00f import parse as wafw00f_parse
from tradecraft.tools.base import Tool


class Wafw00f(Tool):
    tool_id = "wafw00f"

    def run(self, target: str) -> Dict[str, Any]:
        raw = wafw00f_execute.execute(target)
        if raw.error:
            return {"target": target, "wafs_detected": [], "error": raw.error}
        return {"target": target, "wafs_detected": wafw00f_parse.parse_wafs(raw.json_output)}

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        wafs = result.get("wafs_detected")
        if not wafs:
            return []
        host, port = wafw00f_parse.host_port_from_target(params.get("target", ""))
        if not host:
            return []
        return [{"host": host, "port": port or 80, "waf": ", ".join(wafs)}]
