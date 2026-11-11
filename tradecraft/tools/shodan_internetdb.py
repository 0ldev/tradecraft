"""
Shodan InternetDB tool: passive lookup of observed open ports, hostnames, CPEs, and CVEs.
Glues config/tools/shodan_internetdb.yaml to tradecraft.adapters.shodan_internetdb.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.shodan_internetdb import execute as shodan_execute
from tradecraft.adapters.shodan_internetdb import parse as shodan_parse
from tradecraft.tools.base import Tool


class ShodanInternetdb(Tool):
    tool_id = "shodan_internetdb"

    def run(self, ip: str) -> Dict[str, Any]:
        raw_results = shodan_execute.execute(ip)
        parsed = shodan_parse.parse_all(raw_results)
        res = {
            "ip": ip,
            "total_queried": len(raw_results),
            "results": parsed,
            "_full_evidence": {"ip": ip, "results": parsed},
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        ip = params.get("ip", "")
        full = result.pop("_full_evidence", None)
        if not ip or full is None:
            return None
        ips = shodan_execute.normalize_ips(ip)
        canonical_target = ips[0] if ips else ip
        return canonical_target, full, ips[1:]

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        facts = []
        for entry in result.get("results", []):
            if not entry.get("known_to_shodan"):
                continue
            ip_addr = entry.get("ip")
            ports = entry.get("ports", [])
            vulns = entry.get("vulns", [])
            hostnames = entry.get("hostnames", [])
            for i, port in enumerate(ports):
                fact: Dict[str, Any] = {"host": ip_addr, "port": int(port)}
                # hostnames/vulns are host-level in Shodan InternetDB's own
                # schema (one list per IP, not per port) -- attach once, on
                # the first port, instead of repeating the identical list
                # on every open port's Fact. A real run had the same
                # 13-hostname list repeated across 9 port rows for one IP
                # in the generated Attack Surface Inventory table.
                if i == 0:
                    if vulns:
                        fact["shodan_vulns"] = ", ".join(vulns)
                    if hostnames:
                        fact["shodan_hostnames"] = ", ".join(hostnames)
                if result.get("evidence_id"):
                    fact["evidence"] = result["evidence_id"]
                facts.append(fact)
        return facts
