from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.nmap import execute as nmap_execute
from tradecraft.adapters.nmap import parse as nmap_parse
from tradecraft.tools.base import Tool


class NmapScan(Tool):
    tool_id = "nmap_scan"

    def run(self, target: str, depth: str = "standard") -> Dict[str, Any]:
        raw = nmap_execute.execute(target, depth=depth)
        if raw.error:
            return {"target": target, "ports": [], "error": raw.error}
        return {"target": target, "ports": nmap_parse.parse_open_ports(raw.stdout)}

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        host, _ = nmap_execute.parse_host_port(target)
        ev_id = result.get("evidence_id")
        facts = []
        for p in result.get("ports", []):
            f = {
                "host": host,
                "port": p["port"],
                "state": p.get("state"),
                "service": p.get("service"),
                "version": p.get("version"),
            }
            if ev_id:
                f["evidence"] = ev_id
            facts.append(f)
        return facts
