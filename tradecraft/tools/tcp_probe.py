"""
TCP Probe tool: raw single-shot TCP banner grabbing and port ambiguity resolution.
Glues config/tools/tcp_probe.yaml to tradecraft.adapters.tcp_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.tcp_probe.execute import execute as tcp_execute
from tradecraft.adapters.tcp_probe.parse import parse as tcp_parse
from tradecraft.tools.base import Tool


class TcpProbe(Tool):
    tool_id = "tcp_probe"

    def run(
        self,
        target: str,
        port: int,
        ssl_probe: bool = False,
        send_data: str = "",
        timeout: int = 5,
    ) -> Dict[str, Any]:
        result = tcp_execute(
            target=target,
            port=port,
            ssl_probe=ssl_probe,
            send_data=send_data,
            timeout=timeout,
        )
        parsed = tcp_parse(result)

        full_evidence = {
            "target": target,
            "host": result.host,
            "port": result.port,
            "connected": result.connected,
            "ssl_used": result.ssl_used,
            "status": result.status,
            "banner_hex": result.banner_hex,
            "banner_text": result.banner_text,
            "rtt_ms": result.rtt_ms,
            "error": result.error,
            "note": result.note,
        }
        parsed["_full_evidence"] = full_evidence
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        host = result.get("host") or params.get("target", "")
        port = result.get("port")
        if not host or not port:
            return []

        status = result.get("status")
        service = result.get("service")
        banner = result.get("banner")

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
        }

        if status == "open":
            fact["state"] = "open"
            if service:
                fact["service"] = service
            if banner:
                fact["banner"] = banner
            return [fact]
        elif status == "closed_by_peer":
            fact["state"] = "closed"
            fact["note"] = "tcpwrapped/closed by peer immediately"
            return [fact]
        elif status == "refused":
            fact["state"] = "closed"
            return [fact]
        return []
