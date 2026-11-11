from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.sqlmap import execute as sqlmap_execute
from tradecraft.adapters.sqlmap import parse as sqlmap_parse
from tradecraft.tools.base import Tool


class Sqlmap(Tool):
    tool_id = "sqlmap"

    def run(
        self,
        target: str,
        parameter: str = "",
        data: str = "",
        method: str = "GET",
        level: int = 1,
        risk: int = 1,
    ) -> Dict[str, Any]:
        raw = sqlmap_execute.execute(
            target=target,
            parameter=parameter,
            data=data,
            method=method,
            level=level,
            risk=risk,
        )
        if raw.error:
            return {
                "target": target,
                "parameter": parameter,
                "method": method,
                "injectable": False,
                "vulnerabilities": [],
                "error": raw.error,
            }

        parsed = sqlmap_parse.parse_sqlmap_output(
            csv_content=raw.csv_content,
            log_content=raw.log_content,
            stdout=raw.stdout,
        )
        vulnerabilities = parsed.get("vulnerabilities", [])
        injectable = parsed.get("injectable", False)
        dbms = parsed.get("dbms")

        res: Dict[str, Any] = {
            "target": target,
            "parameter": parameter,
            "method": method,
            "injectable": injectable,
            "dbms": dbms,
            "total_vulnerabilities": len(vulnerabilities),
            "duration_seconds": round(raw.duration_seconds, 1),
        }

        if len(vulnerabilities) > 10:
            res["vulnerabilities"] = vulnerabilities[:10]
            res["omitted_vulnerabilities"] = len(vulnerabilities) - 10
            res["note"] = (
                f"{len(vulnerabilities) - 10} more injection vulnerabilities omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["vulnerabilities"] = vulnerabilities

        res["_full_evidence"] = {
            "target": target,
            "parameter": parameter,
            "method": method,
            "injectable": injectable,
            "dbms": dbms,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = sqlmap_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            # An error/timeout is an execution failure, not a tested-and-
            # clean result -- must not be recorded as sqli_tested.
            return []
        host, port = sqlmap_parse.host_port_from_target(target)
        injectable = result.get("injectable", False)
        dbms = result.get("dbms")

        fact: Dict[str, Any] = {"host": host, "port": port}
        if injectable:
            fact["sqli_injectable"] = True
            if dbms:
                fact["sqli_dbms"] = dbms
        else:
            fact["sqli_tested"] = True

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
