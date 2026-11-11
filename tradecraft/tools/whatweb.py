from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.whatweb import execute as whatweb_execute
from tradecraft.adapters.whatweb import parse as whatweb_parse
from tradecraft.tools.base import Tool


class WhatWeb(Tool):
    tool_id = "whatweb"

    def run(self, target: str) -> Dict[str, Any]:
        raw = whatweb_execute.execute(target)
        if raw.error:
            return {"target": target, "tech": [], "error": raw.error}
        fingerprint = whatweb_parse.parse_fingerprint(raw.stdout)
        if fingerprint is None:
            return {"target": target, "tech": []}
        return {"target": target, **fingerprint}

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        tech = result.get("tech")
        host, port = result.get("host"), result.get("port")
        if not tech or not host or port is None:
            return []
        return [{"host": host, "port": int(port), "whatweb_tech": ", ".join(tech)}]
