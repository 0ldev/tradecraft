from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.ffuf_vhost import execute as ffuf_vhost_execute
from tradecraft.adapters.ffuf_vhost import parse as ffuf_vhost_parse
from tradecraft.tools.base import Tool


class FfufVhost(Tool):
    tool_id = "ffuf_vhost"

    def run(self, target: str, wordlist: str = "vhosts") -> Dict[str, Any]:
        raw = ffuf_vhost_execute.execute(target=target, wordlist=wordlist)
        if raw.error:
            return {
                "target": target,
                "vhosts_found": 0,
                "vhosts": [],
                "error": raw.error,
            }

        vhosts = ffuf_vhost_parse.parse_vhosts(
            json_output=raw.json_output,
            baseline=raw.baseline,
            host=raw.host,
        )

        res: Dict[str, Any] = {
            "target": target,
            "vhosts_found": len(vhosts),
        }
        if len(vhosts) > 15:
            res["vhosts"] = vhosts[:15]
            res["omitted_vhosts"] = len(vhosts) - 15
            res["note"] = (
                f"{len(vhosts) - 15} more vhosts omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["vhosts"] = vhosts

        baseline_dict = None
        if raw.baseline:
            baseline_dict = {
                "status_code": raw.baseline.status_code,
                "length": raw.baseline.length,
            }

        res["_full_evidence"] = {
            "target": target,
            "host": raw.host,
            "port": raw.port,
            "vhosts_found": len(vhosts),
            "vhosts": vhosts,
            "baseline": baseline_dict,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = full.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []

        base_url, host, port = ffuf_vhost_execute.normalize_target(target)
        vhosts = result.get("vhosts", [])
        if not vhosts:
            return []

        facts: List[Dict[str, Any]] = []
        for item in vhosts:
            fact: Dict[str, Any] = {
                "host": item["vhost"],
                "port": port,
                "vhost_discovered_via": host,
                "http_status": item["status_code"],
            }
            if result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]
            facts.append(fact)
        return facts
