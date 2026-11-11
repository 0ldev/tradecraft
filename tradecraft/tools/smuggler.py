from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.smuggler import execute as smuggler_execute
from tradecraft.adapters.smuggler import parse as smuggler_parse
from tradecraft.tools.base import Tool


class Smuggler(Tool):
    tool_id = "smuggler"

    def is_available(self) -> bool:
        return smuggler_execute.find_script() is not None

    def run(self, target: str) -> Dict[str, Any]:
        raw = smuggler_execute.execute(target=target)
        parsed = smuggler_parse.parse_smuggler_output(raw)
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "target": target,
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target") or result.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target") or result.get("target", "")
        if not target or not result.get("vulnerable"):
            return []
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return [
            {
                "host": host,
                "port": port,
                "http_smuggling_tested": True,
                "http_smuggling_vulnerable": True,
                "desync_types": result.get("desync_types", []),
            }
        ]
