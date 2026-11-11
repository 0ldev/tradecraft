from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.http_request.parse import host_port_from_url
from tradecraft.adapters.ssrf_probe import execute as ssrf_execute
from tradecraft.adapters.ssrf_probe import parse as ssrf_parse
from tradecraft.tools.base import Tool


class SsrfProbe(Tool):
    tool_id = "ssrf_probe"

    def run(
        self,
        target: str,
        inject_location: str,
        method: str = "",
        json_body_template: str = "",
        header_name: str = "",
        oob_domain: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = ssrf_execute.execute(
            target=target,
            inject_location=inject_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            oob_domain=oob_domain,
            timeout=timeout,
        )
        return ssrf_parse.parse_ssrf_result(raw)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = host_port_from_url(target)
        if not host:
            return []
        fact: Dict[str, Any] = {"host": host, "port": port}
        if result.get("hits"):
            fact["ssrf_vulnerable"] = True
            loc = params.get("inject_location", "")
            fact["vulnerability"] = f"SSRF vulnerability indicated at location '{loc}'" if loc else "SSRF vulnerability indicated"
            fact["severity"] = "high"
        else:
            fact["ssrf_tested"] = True
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
