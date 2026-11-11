"""
Cero tool: Certificate Transparency subdomain discovery.
Glues config/tools/cero.yaml to tradecraft.adapters.cero.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from tradecraft.adapters.cero.execute import execute as cero_execute
from tradecraft.adapters.cero.parse import parse_domains as cero_parse_domains
from tradecraft.tools.base import Tool


class Cero(Tool):
    tool_id = "cero"

    def run(self, target: str) -> Dict[str, Any]:
        raw = cero_execute(target)
        if raw.error:
            return {"target": target, "domains": [], "error": raw.error}
        domains = cero_parse_domains(raw.domains, target)
        return {
            "target": target,
            "domains_found": len(domains),
            "domains": domains,
        }

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        if not target:
            return None
        return target, result
