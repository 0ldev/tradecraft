from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.ghauri import execute as ghauri_execute
from tradecraft.adapters.ghauri import parse as ghauri_parse
from tradecraft.tools.base import Tool


class Ghauri(Tool):
    tool_id = "ghauri"

    def is_available(self) -> bool:
        return ghauri_execute.find_binary() is not None

    def run(
        self,
        target: str,
        parameter: str = "",
        data: str = "",
        headers: str = "",
        level: int = 1,
    ) -> Dict[str, Any]:
        raw = ghauri_execute.execute(
            target=target,
            parameter=parameter,
            data=data,
            headers=headers,
            level=level,
        )
        parsed = ghauri_parse.parse_ghauri_output(raw)
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "target": target,
                "parameter": parameter,
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
                "sqli_tested": True,
                "sqli_vulnerable": True,
                "dbms": result.get("dbms", ""),
                "parameter": result.get("parameter", ""),
            }
        ]
