"""
HTML form discovery and input parameter probing
for SSRF (cloud metadata), SQL injection, and differential SSTI.
Classified as destructive: false (confirmation-only read probe).
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.form_fuzzer import execute as form_execute
from tradecraft.adapters.form_fuzzer import parse as form_parse
from tradecraft.tools.base import Tool


class FormFuzzer(Tool):
    tool_id = "form_fuzzer"

    def run(
        self,
        target: str,
        internal_url: str = "",
        target_param: str = "",
    ) -> Dict[str, Any]:
        raw = form_execute.execute(
            target=target,
            internal_url=internal_url,
            target_param=target_param,
        )
        parsed = form_parse.parse_form_fuzzer_result(raw)

        if parsed.get("vulnerable"):
            parsed["_full_evidence"] = {
                "target": target,
                "internal_url": internal_url,
                "target_param": target_param,
                "forms_found": parsed.get("forms_found"),
                "fields_tested": parsed.get("fields_tested"),
                "vulnerabilities": parsed.get("vulnerabilities"),
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = form_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        vulns = result.get("vulnerabilities", [])
        if not target or not vulns:
            return []

        host, port = form_parse.parse_host_port(target)
        fact: Dict[str, Any] = {"host": host, "port": port}

        types = {v.get("vulnerability_type") for v in vulns if isinstance(v, dict)}
        if "ssrf" in types:
            fact["ssrf_vulnerable"] = True
            fact["cloud_metadata_exposed"] = True
        if "sqli" in types:
            fact["sqli_vulnerable"] = True
        if "ssti" in types:
            fact["ssti_vulnerable"] = True
        if "xss" in types:
            fact["xss_vulnerable"] = True

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
