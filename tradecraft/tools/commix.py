from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.commix.execute import execute as run_commix
from tradecraft.adapters.commix.parse import (
    host_port_from_target,
    parse_commix_output,
)
from tradecraft.tools.base import Tool


class Commix(Tool):
    tool_id = "commix"

    def run(
        self,
        target: str,
        parameter: str = "",
        data: str = "",
        method: str = "GET",
        level: int = 1,
    ) -> Dict[str, Any]:
        raw = run_commix(
            target=target,
            parameter=parameter,
            data=data,
            method=method,
            level=level,
        )
        if raw.error:
            return {
                "target": target,
                "parameter": parameter,
                "method": method,
                "vulnerable": False,
                "total_injections": 0,
                "injections": [],
                "error": raw.error,
            }

        parsed = parse_commix_output(
            stdout=raw.stdout,
            logs_content=raw.logs_content,
            target_url=raw.target_url,
            tested_param=raw.parameter,
        )

        injections = parsed.get("injections", [])
        res: Dict[str, Any] = {
            "target": target,
            "parameter": parsed.get("parameter", parameter),
            "method": method,
            "vulnerable": parsed.get("vulnerable", False),
            "total_injections": parsed.get("total_injections", 0),
            "target_os": parsed.get("target_os", "unknown"),
        }

        if len(injections) > 5:
            res["injections"] = injections[:5]
            res["omitted_injections"] = len(injections) - 5
            res["note"] = (
                f"{len(injections) - 5} more injection points omitted to conserve context. "
                "Use search_evidence to inspect details."
            )
        else:
            res["injections"] = injections

        res["_full_evidence"] = {
            "target": target,
            "parameter": parameter,
            "data": data,
            "method": method,
            "vulnerable": parsed.get("vulnerable", False),
            "total_injections": parsed.get("total_injections", 0),
            "target_os": parsed.get("target_os", "unknown"),
            "injections": injections,
            "raw_logs": raw.logs_content,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []
        host, port = host_port_from_target(target)
        vulnerable = result.get("vulnerable", False)
        total_injections = result.get("total_injections", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        fact["cmdi_tested"] = True
        if total_injections > 0:
            fact["command_injection_points"] = total_injections
        if vulnerable:
            fact["command_injection_vulnerable"] = True
            if result.get("target_os") and result["target_os"] != "unknown":
                fact["target_os"] = result["target_os"]
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
