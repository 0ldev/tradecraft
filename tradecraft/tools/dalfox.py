from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.dalfox import execute as dalfox_execute
from tradecraft.adapters.dalfox import parse as dalfox_parse
from tradecraft.tools.base import Tool


class Dalfox(Tool):
    tool_id = "dalfox"

    def run(
        self,
        target: str,
        parameter: str = "",
        data: str = "",
        method: str = "GET",
        cookie: str = "",
        header: str = "",
    ) -> Dict[str, Any]:
        raw = dalfox_execute.execute(
            target=target,
            parameter=parameter,
            data=data,
            method=method,
            cookie=cookie,
            header=header,
        )
        if raw.error and not raw.timed_out:
            return {
                "target": target,
                "parameter": parameter,
                "method": method,
                "findings": [],
                "total_findings": 0,
                "vulnerable_count": 0,
                "error": raw.error,
            }

        parsed = dalfox_parse.parse_dalfox_output(
            json_content=raw.json_content,
            stdout=raw.stdout,
        )

        res: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "method": method,
            "total_findings": parsed["total_findings"],
            "vulnerable_count": parsed["vulnerable_count"],
            "reflected_count": parsed["reflected_count"],
            "dom_count": parsed["dom_count"],
        }
        if raw.timed_out:
            res["timed_out"] = True
            res["timeout_seconds"] = raw.timeout_seconds
            res["timeout_note"] = (
                "The scan was stopped at its timeout, so XSS testing of this parameter is "
                "incomplete. Missing findings do not mean the parameter is safe."
            )
            if not parsed["findings"] and not raw.stdout.strip():
                res["error"] = raw.error

        findings = parsed["findings"]
        if len(findings) > 10:
            res["findings"] = findings[:10]
            res["omitted_findings"] = len(findings) - 10
            res["note"] = (
                f"{len(findings) - 10} more findings omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["findings"] = findings

        res["_full_evidence"] = {
            "target": target,
            "parameter": parameter,
            "data": data,
            "method": method,
            "total_findings": parsed["total_findings"],
            "vulnerable_count": parsed["vulnerable_count"],
            "reflected_count": parsed["reflected_count"],
            "dom_count": parsed["dom_count"],
            "findings": findings,
            "meta": parsed.get("meta", {}),
            "timed_out": bool(raw.timed_out),
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = dalfox_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = dalfox_parse.host_port_from_target(target)
        total_findings = result.get("total_findings", len(result.get("findings", [])))
        vuln_count = result.get("vulnerable_count", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        # A timed-out run did not finish testing, so it must not record the
        # parameter as tested. Real findings from it are still recorded.
        if not result.get("timed_out"):
            fact["xss_tested"] = True
        if total_findings > 0:
            fact["dalfox_findings"] = total_findings
        if vuln_count > 0:
            fact["dalfox_xss_vulnerable"] = True
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
