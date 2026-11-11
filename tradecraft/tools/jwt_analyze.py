"""
JWT Analyze tool: tests for the classic 'alg=none' signature-bypass vulnerability.
Glues config/tools/jwt_analyze.yaml to tradecraft.adapters.jwt_analyze.
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.jwt_analyze import execute as jwt_execute
from tradecraft.adapters.jwt_analyze import parse as jwt_parse
from tradecraft.tools.base import Tool


class JwtAnalyze(Tool):
    tool_id = "jwt_analyze"

    def run(self, target: str, token: str) -> Dict[str, Any]:
        try:
            header, payload = jwt_execute.decode_jwt_claims(token)
        except ValueError as exc:
            return {"target": target, "error": f"invalid JWT: {exc}"}

        forged = jwt_execute.forge_none_alg_token(header, payload)
        diff = jwt_execute.run_differential(target, forged)
        if diff.error:
            return {"target": target, "error": diff.error, "forged_token": forged}

        res = {"target": target, **jwt_parse.parse_result(diff.baseline_status, diff.forged_status)}
        if res["vulnerable"]:
            res["forged_token"] = forged
            res["technique"] = "none_algorithm_forgery"

        res["_full_evidence"] = {
            "target": target,
            "original_header": header,
            "original_payload": payload,
            "forged_token": forged,
            "baseline_status": diff.baseline_status,
            "forged_status": diff.forged_status,
            "vulnerable": res["vulnerable"],
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urlparse(target)
        canonical_target = parsed.netloc or target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        target = params.get("target", "")
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "jwt_alg_none_bypass": "vulnerable",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
