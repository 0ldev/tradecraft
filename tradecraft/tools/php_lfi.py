"""
Tests a parameter on a target web application
for Local File Inclusion (LFI) vulnerabilities.
Classified as destructive: false (confirmation-only read probe).
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.php_lfi import execute as lfi_execute
from tradecraft.adapters.php_lfi import parse as lfi_parse
from tradecraft.tools.base import Tool


class PhpLfi(Tool):
    tool_id = "php_lfi"

    def run(
        self,
        target: str,
        parameter: str,
        file_path: str = "",
    ) -> Dict[str, Any]:
        raw = lfi_execute.execute(
            target=target,
            parameter=parameter,
            file_path=file_path,
        )
        parsed = lfi_parse.parse_lfi_result(raw)

        if parsed.get("vulnerable"):
            parsed["_full_evidence"] = {
                "target": target,
                "parameter": parameter,
                "payload_used": parsed.get("payload_used"),
                "file_disclosed": parsed.get("file_disclosed"),
                "snippet": parsed.get("snippet"),
                "tested_payloads_count": parsed.get("tested_payloads_count"),
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = lfi_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("vulnerable"):
            return []
        host, port = lfi_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "lfi_vulnerable": True,
            "lfi_parameter": result.get("parameter"),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
