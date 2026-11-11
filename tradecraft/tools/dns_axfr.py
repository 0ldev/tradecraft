"""
DnsAxfr tool: tests domain authoritative nameservers for DNS zone transfer (AXFR) misconfiguration.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.dns_axfr import execute as dns_axfr_execute
from tradecraft.adapters.dns_axfr import parse as dns_axfr_parse
from tradecraft.tools.base import Tool


class DnsAxfr(Tool):
    tool_id = "dns_axfr"

    def run(self, target: str) -> Dict[str, Any]:
        raw = dns_axfr_execute.execute(target)
        if not raw:
            return {
                "target": target,
                "nameservers_tested": [],
                "vulnerable": False,
                "note": "no nameservers resolved for this target",
            }
        parsed = dns_axfr_parse.parse_all(raw)
        res: Dict[str, Any] = {
            "target": target,
            **parsed,
            "vulnerable": bool(parsed["vulnerable_nameservers"]),
        }
        res["_full_evidence"] = {
            "target": target,
            "raw": {ns: r.stdout for ns, r in raw.items()},
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        return (target, full) if (target and full is not None) else None

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        return [{
            "host": params.get("target", ""),
            "port": 53,
            "dns_zone_transfer": f"vulnerable via {', '.join(result['vulnerable_nameservers'])}",
            **({"evidence": result["evidence_id"]} if result.get("evidence_id") else {}),
        }]
