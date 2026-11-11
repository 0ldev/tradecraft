"""
ASN Discovery tool: organization network range and ASN enumeration.
Glues config/tools/asn_discovery.yaml to tradecraft.adapters.asn_discovery.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from tradecraft.adapters.asn_discovery.execute import execute as asn_execute
from tradecraft.adapters.asn_discovery.parse import parse_result as asn_parse_result
from tradecraft.tools.base import Tool


class AsnDiscovery(Tool):
    tool_id = "asn_discovery"

    def run(self, target: str) -> Dict[str, Any]:
        raw = asn_execute(target)
        if raw.error:
            return {"target": target, "error": raw.error}
        parsed = asn_parse_result(raw)
        out = {
            "target": target,
            "org_name": raw.org_name,
            "discovered_asns": parsed["asns"],
            "discovered_cidrs": parsed["cidrs"],
        }
        if raw.skipped_private:
            out["note"] = "skipped: target resolves to a private/non-global IP"
        return out

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        if not target:
            return None
        return target, result
