"""
Corsy tool: tests endpoints for CORS misconfigurations.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.corsy import execute as corsy_execute
from tradecraft.adapters.corsy import parse as corsy_parse
from tradecraft.tools.base import Tool


class Corsy(Tool):
    tool_id = "corsy"

    def run(self, url: str, headers: Optional[str] = None) -> Dict[str, Any]:
        raw = corsy_execute.execute(url, headers=headers)
        if raw.error:
            return {
                "url": url,
                "error": raw.error,
                "misconfigured": False,
                "findings": [],
            }
        parsed = corsy_parse.parse_corsy_output(raw.stdout, default_url=url)
        res: Dict[str, Any] = {
            "url": url,
            **parsed,
        }
        res["_full_evidence"] = {
            "url": url,
            "raw": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        url = params.get("url", "")
        full = result.pop("_full_evidence", None)
        if not url or full is None:
            return None
        parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
        host = parsed.hostname or url
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("misconfigured"):
            return []
        url = params.get("url", "")
        parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        facts: List[Dict[str, Any]] = []
        for finding in result.get("findings", []):
            cls_name = finding.get("class") or finding.get("description") or "CORS misconfiguration"
            facts.append({
                "host": host,
                "port": port,
                "cors_misconfig": f"{cls_name} ({finding.get('url', url)})",
                **({"evidence": result["evidence_id"]} if result.get("evidence_id") else {}),
            })
        return facts
