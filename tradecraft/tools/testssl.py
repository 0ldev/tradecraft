from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.testssl import execute as testssl_execute
from tradecraft.adapters.testssl import parse as testssl_parse
from tradecraft.tools.base import Tool


class TestSsl(Tool):
    tool_id = "testssl"

    def run(self, target: str) -> Dict[str, Any]:
        raw = testssl_execute.execute(target)
        if raw.error:
            return {"target": target, "findings": [], "error": raw.error}
        findings = testssl_parse.parse_findings(raw.csv_output)
        all_rows = testssl_parse.parse_all_rows(raw.csv_output)
        res: Dict[str, Any] = {"target": target}
        if len(findings) > 10:
            res["findings"] = findings[:10]
            res["omitted_findings"] = len(findings) - 10
            res["note"] = f"{len(findings) - 10} more findings omitted to conserve context. Use read_evidence to inspect all."
        else:
            res["findings"] = findings
            if not findings:
                # An empty findings list means no protocol/cipher/named-vuln row
                # came back flagged -- it does NOT mean testssl checked nothing.
                # Say what was actually checked so an empty result isn't mistaken
                # for "nothing was tested" or taken at face value without
                # hydrating; read_evidence now returns the real unfiltered rows
                # (all_rows below), not another copy of this same empty list.
                res["note"] = (
                    f"{len(all_rows)} row(s) checked (protocols, ciphers, named "
                    "vulnerabilities, headers); none came back flagged. "
                    "Call read_evidence for the full unfiltered output."
                )
        res["_full_evidence"] = {"findings": findings, "all_rows": all_rows}
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        host, port = testssl_parse.host_port_from_target(params.get("target", ""))
        findings = result.get("findings")
        severity = testssl_parse.worst_severity(findings) if findings else None

        fact: Dict[str, Any] = {"host": host, "port": port}
        if severity is not None:
            fact["tls_worst_severity"] = severity
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
