from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.http_request.parse import host_port_from_url
from tradecraft.adapters.open_redirect_probe import execute as redirect_execute
from tradecraft.adapters.open_redirect_probe import parse as redirect_parse
from tradecraft.tools.base import Tool


class OpenRedirectProbe(Tool):
    tool_id = "open_redirect_probe"

    def run(self, target: str, param: str = "", timeout: int = 10) -> Dict[str, Any]:
        raw = redirect_execute.execute(target=target, param=param, timeout=timeout)
        return redirect_parse.parse_open_redirect_result(raw)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = host_port_from_url(target)
        if not host:
            return []
        fact: Dict[str, Any] = {"host": host, "port": port}
        if result.get("vulnerable_params") or result.get("hits"):
            fact["open_redirect_vulnerable"] = True
            vulns = result.get("vulnerable_params") or []
            fact["vulnerability"] = f"Open redirect confirmed on parameter(s): {', '.join(vulns)}" if vulns else "Open redirect confirmed"
            fact["severity"] = "medium"
        else:
            fact["open_redirect_tested"] = True
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
