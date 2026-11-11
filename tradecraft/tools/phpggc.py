"""
Confirms PHP object injection by generating
a framework gadget chain and submitting it to a suspected unserialize()
sink. Classified as destructive: true (it delivers a working RCE
payload, though the fixed `id` command leaves no persistent artifact).
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.phpggc import execute as phpggc_execute
from tradecraft.adapters.phpggc import parse as phpggc_parse
from tradecraft.tools.base import Tool


class Phpggc(Tool):
    tool_id = "phpggc"

    def is_available(self) -> bool:
        # required_binary="php" alone would report available even when
        # the phpggc script itself isn't installed -- same gap tplmap's
        # tool already guards against.
        if not super().is_available():
            return False
        return phpggc_execute.find_script() is not None

    def run(
        self,
        target: str,
        parameter: str,
        method: str = "GET",
        framework: str = "",
        cookie: str = "",
    ) -> Dict[str, Any]:
        raw = phpggc_execute.execute(
            target=target,
            parameter=parameter,
            method=method,
            framework=framework,
            cookie=cookie,
        )
        parsed = phpggc_parse.parse_result(raw)

        if parsed.get("vulnerable"):
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "parameter": parsed.get("parameter"),
                "method": parsed.get("method"),
                "framework": parsed.get("framework"),
                "gadget": parsed.get("gadget"),
                "status_code": parsed.get("status_code"),
                "snippet": parsed.get("snippet"),
                "payload_b64": raw.payload_b64,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = phpggc_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error") or not result.get("vulnerable"):
            return []
        host, port = phpggc_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "php_deserialization_rce": True,
            "phpggc_gadget": result.get("gadget"),
            "phpggc_parameter": result.get("parameter"),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
