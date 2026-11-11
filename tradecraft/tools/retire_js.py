"""
RetireJs tool: checks a web page's JavaScript libraries against known-vulnerability databases.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.retire_js import execute as retire_js_execute
from tradecraft.adapters.retire_js import parse as retire_js_parse
from tradecraft.tools.base import Tool


class RetireJs(Tool):
    tool_id = "retire_js"

    def run(self, target: str) -> Dict[str, Any]:
        raw = retire_js_execute.execute(target)
        if raw.error:
            return {
                "target": target,
                "error": raw.error,
                "vulnerable": False,
                "vulnerable_components": [],
                "scripts_downloaded": raw.scripts_downloaded,
            }
        parsed = retire_js_parse.parse_retire_output(raw.stdout)
        res: Dict[str, Any] = {
            "target": target,
            "scripts_downloaded": raw.scripts_downloaded,
            **parsed,
        }
        res["_full_evidence"] = {
            "target": target,
            "raw": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        target = params.get("target", "")
        parsed = urllib.parse.urlsplit(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        facts: List[Dict[str, Any]] = []
        for c in result.get("vulnerable_components", []):
            comp_str = f"{c['component']}@{c['version']}"
            facts.append({
                "host": host,
                "port": port,
                "vulnerable_js_library": comp_str,
                **({"evidence": result["evidence_id"]} if result.get("evidence_id") else {}),
            })
        return facts
