"""
HTTP Smuggling Probe tool: single-shot differential detection of CL.TE and
TE.CL request framing discrepancies. Glues config/tools/http_smuggling_probe.yaml
to tradecraft.adapters.http_smuggling_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.http_smuggling_probe.execute import execute as smuggling_execute
from tradecraft.adapters.http_smuggling_probe.parse import (
    VERDICT_CL_TE,
    VERDICT_TE_CL,
    parse as smuggling_parse,
)
from tradecraft.tools.base import Tool


class HttpSmugglingProbe(Tool):
    tool_id = "http_smuggling_probe"

    def run(
        self,
        target: str,
        port: int = 443,
        ssl_probe: bool = True,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        run = smuggling_execute(
            target=target,
            port=port,
            ssl_probe=ssl_probe,
            timeout=timeout,
        )
        parsed = smuggling_parse(run)

        parsed["_full_evidence"] = {
            "target": target,
            "host": run.host,
            "port": run.port,
            "ssl_used": run.ssl_used,
            "nonce": run.nonce,
            "timeout_s": run.timeout_s,
            "error": run.error,
            "variants": [
                {
                    "variant": v.variant,
                    "status": v.status,
                    "connected": v.connected,
                    "request_head": v.request_head,
                    "status_codes": v.status_codes,
                    "bytes_received": v.bytes_received,
                    "response_head": v.response_head.decode("latin-1", errors="replace"),
                    "first_response_ms": v.first_response_ms,
                    "elapsed_ms": v.elapsed_ms,
                    "error": v.error,
                }
                for v in run.variants
            ],
        }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Only a positive discrepancy is recorded as a fact; clean or errored
        # runs add nothing to the port record.
        host = result.get("host") or params.get("target", "")
        port = result.get("port")
        verdict = result.get("verdict")
        if not host or not port:
            return []
        if verdict in (VERDICT_CL_TE, VERDICT_TE_CL):
            return [{
                "host": host,
                "port": port,
                "http_smuggling": verdict,
            }]
        return []
