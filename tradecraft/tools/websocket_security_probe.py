from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.websocket_security_probe import execute as wsp_execute
from tradecraft.adapters.websocket_security_probe import parse as wsp_parse
from tradecraft.tools.base import Tool


class WebsocketSecurityProbe(Tool):
    tool_id = "websocket_security_probe"

    def run(
        self,
        target: str,
        path: str = "/",
        origins_to_test: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        run = wsp_execute.execute(target=target, path=path, origins_to_test=origins_to_test, cookie=cookie, timeout=timeout)
        parsed = wsp_parse.parse(run)
        if "error" in parsed:
            return parsed

        parsed["_full_evidence"] = dict(parsed)
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        host = result.get("host") or params.get("target", "")
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result or not result.get("vulnerable"):
            return []
        host = result.get("host")
        port = result.get("port")
        if not host or not port:
            return []
        evidence_id = result.get("evidence_id")
        origins = ", ".join(result.get("cross_origin_accepted", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"WebSocket handshake accepts cross-origin Origin header(s) ({origins}) -- CSWSH risk",
            "severity": "high",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
