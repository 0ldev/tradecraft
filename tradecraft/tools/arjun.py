from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.arjun import execute as arjun_execute
from tradecraft.adapters.arjun import parse as arjun_parse
from tradecraft.tools.base import Tool


class Arjun(Tool):
    tool_id = "arjun"

    def run(
        self,
        target: str,
        path: str = "/",
        method: str = "GET",
        wordlist: str = "small",
    ) -> Dict[str, Any]:
        raw = arjun_execute.execute(
            target=target,
            path=path,
            method=method,
            wordlist=wordlist,
        )
        if raw.error:
            return {
                "target": target,
                "path": path,
                "method": method,
                "wordlist": wordlist,
                "parameters": [],
                "error": raw.error,
            }

        parsed = arjun_parse.parse_arjun_output(raw.json_output, raw.stdout)
        parameters = parsed.get("parameters", [])

        res: Dict[str, Any] = {
            "target": target,
            "path": path,
            "method": method,
            "wordlist": wordlist,
            "total_parameters": len(parameters),
        }

        if len(parameters) > 20:
            res["parameters"] = parameters[:20]
            res["omitted_parameters"] = len(parameters) - 20
            res["note"] = (
                f"{len(parameters) - 20} more parameters omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["parameters"] = parameters

        res["_full_evidence"] = {
            "target": target,
            "path": path,
            "method": method,
            "wordlist": wordlist,
            "total_parameters": len(parameters),
            "parameters": parameters,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = arjun_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = arjun_parse.host_port_from_target(target)
        total_params = result.get("total_parameters", len(result.get("parameters", [])))

        fact: Dict[str, Any] = {"host": host, "port": port, "arjun_tested": True}
        if total_params > 0:
            fact["arjun_params_discovered"] = total_params
            raw_params = result.get("parameters") or []
            if raw_params:
                sample = sorted({str(p) for p in raw_params})[:10]
                fact["arjun_params_sample"] = ",".join(sample)
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
