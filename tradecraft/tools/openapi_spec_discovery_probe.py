"""
OpenAPI Spec Discovery Probe tool: fetches common OpenAPI/Swagger spec
paths and enumerates the full documented API surface. Glues
config/tools/openapi_spec_discovery_probe.yaml to
tradecraft.adapters.openapi_spec_discovery_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.openapi_spec_discovery_probe.execute import execute as spec_execute
from tradecraft.adapters.openapi_spec_discovery_probe.parse import parse as spec_parse
from tradecraft.tools.base import Tool

# Same SRI_DISPLAY_CAP-style pattern response_security_audit uses to
# conserve context on a spec with a very large number of endpoints.
ENDPOINT_DISPLAY_CAP = 50


class OpenApiSpecDiscoveryProbe(Tool):
    tool_id = "openapi_spec_discovery_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        result = spec_execute(target=target, timeout=timeout)
        parsed = spec_parse(result)
        parsed["_full_evidence"] = {
            "target": target,
            "base_url": result.base_url,
            "specs_found": [dict(s) for s in parsed["specs_found"]],
        }

        for spec in parsed["specs_found"]:
            full_endpoints = spec["endpoints"]
            if len(full_endpoints) > ENDPOINT_DISPLAY_CAP:
                spec["endpoints"] = full_endpoints[:ENDPOINT_DISPLAY_CAP]
                spec["endpoints_omitted"] = len(full_endpoints) - ENDPOINT_DISPLAY_CAP
                spec["note"] = (
                    f"{len(full_endpoints) - ENDPOINT_DISPLAY_CAP} more endpoints omitted to conserve "
                    "context. Use read_evidence to inspect all."
                )

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        facts: List[Dict[str, Any]] = []
        for spec in result.get("specs_found", []):
            fact: Dict[str, Any] = {
                "host": target,
                "port": 443,
                "vulnerability": f"Publicly reachable OpenAPI/Swagger spec at {spec['path']} "
                                  f"({spec['endpoint_count']} endpoints documented)",
                "severity": "low",
            }
            if spec.get("of_interest"):
                fact["vulnerability"] += f", including {len(spec['of_interest'])} admin/internal/debug/test-looking path(s)"
                fact["severity"] = "medium"
            facts.append(fact)
        return facts
