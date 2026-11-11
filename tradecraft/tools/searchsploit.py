from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.searchsploit.execute import execute as run_searchsploit
from tradecraft.adapters.searchsploit.parse import (
    host_port_from_target,
    parse_searchsploit_output,
)
from tradecraft.tools.base import Tool


class Searchsploit(Tool):
    tool_id = "searchsploit"

    def run(
        self,
        query: str = "",
        cve: str = "",
        edb_id: str = "",
        target: str = "",
    ) -> Dict[str, Any]:
        raw = run_searchsploit(query=query, cve=cve, edb_id=edb_id)
        if raw.error:
            return {
                "query": query or cve or edb_id,
                "target": target,
                "total_exploits": 0,
                "exploits": [],
                "error": raw.error,
            }

        parsed = parse_searchsploit_output(
            stdout=raw.stdout,
            query=raw.query,
            cve=raw.cve,
            edb_id=raw.edb_id,
            file_content=raw.file_content,
            file_path=raw.file_path,
        )

        res: Dict[str, Any] = {
            "mode": parsed.get("mode", "search"),
            "target": target,
        }

        if parsed.get("mode") == "examine":
            res.update({
                "edb_id": parsed.get("edb_id", ""),
                "title": parsed.get("title", ""),
                "url": parsed.get("url", ""),
                "codes": parsed.get("codes", ""),
                "verified": parsed.get("verified", False),
                "path": parsed.get("path", ""),
                "poc_content": parsed.get("poc_content", ""),
            })
        else:
            exploits = parsed.get("exploits", [])
            res.update({
                "query": parsed.get("query", ""),
                "total_exploits": len(exploits),
            })
            if len(exploits) > 10:
                res["exploits"] = exploits[:10]
                res["omitted_exploits"] = len(exploits) - 10
                res["note"] = (
                    f"{len(exploits) - 10} more exploits omitted to conserve context. "
                    "Use search_evidence to inspect details, or pass edb_id to view a PoC."
                )
            else:
                res["exploits"] = exploits

        res["_full_evidence"] = {
            "query": query,
            "cve": cve,
            "edb_id": edb_id,
            "target": target,
            "parsed": parsed,
            "raw_stdout": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "") or params.get("query", "") or params.get("cve", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = host_port_from_target(target)
        canonical = host if host else target
        return canonical, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = host_port_from_target(target)
        total_exploits = result.get("total_exploits", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total_exploits > 0:
            fact["known_exploits_count"] = total_exploits
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
