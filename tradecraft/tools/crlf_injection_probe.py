"""
CRLF injection probe tool: injects a CRLF sequence plus a fake header line
into one query parameter and checks the parsed response headers for it.
Glues config/tools/crlf_injection_probe.yaml to
tradecraft.adapters.crlf_injection_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.crlf_injection_probe import execute as crlf_execute
from tradecraft.adapters.crlf_injection_probe import parse as crlf_parse
from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.tools.base import Tool


class CrlfInjectionProbe(Tool):
    tool_id = "crlf_injection_probe"

    def run(
        self,
        target: str,
        parameter: str,
        injected_header_name: str = "X-Tradecraft-CRLF-Test",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = crlf_execute.execute(
            target=target,
            parameter=parameter,
            injected_header_name=injected_header_name,
            timeout=timeout,
        )
        parsed = crlf_parse.parse(raw)
        parsed["_full_evidence"] = {
            "probe_url": raw.probe_url,
            "marker": raw.marker,
            "headers": raw.headers,
        }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        if full is None or not params.get("target"):
            return None
        target = params["target"]
        return (evidence_target_from_url(target) or target), full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = host_port_from_url(target)
        if not host:
            return []
        fact: Dict[str, Any] = {"host": host, "port": port}
        if result.get("vulnerable"):
            fact["crlf_vulnerable"] = True
            fact["vulnerability"] = f"CRLF injection / HTTP response splitting confirmed via parameter '{params.get('parameter', '')}'"
            fact["severity"] = "medium"
        else:
            fact["crlf_tested"] = True
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
