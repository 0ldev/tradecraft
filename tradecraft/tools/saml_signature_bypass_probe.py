from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.saml_signature_bypass_probe import execute as ssbp_execute
from tradecraft.adapters.saml_signature_bypass_probe import parse as ssbp_parse
from tradecraft.tools.base import Tool


class SamlSignatureBypassProbe(Tool):
    tool_id = "saml_signature_bypass_probe"

    def run(self, target: str, saml_response: str, timeout: int = 10) -> Dict[str, Any]:
        raw = ssbp_execute.execute(target=target, saml_response=saml_response, timeout=timeout)
        if raw.error:
            return {"target": target, "error": raw.error}

        result = ssbp_parse.parse(raw)
        result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result or not result.get("vulnerable"):
            return []
        parsed = urllib.parse.urlsplit(result.get("target", "") or params.get("target", ""))
        host = parsed.hostname or params.get("target", "")
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        evidence_id = result.get("evidence_id")
        mutations = ", ".join(result.get("accepted_mutations", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"SAML signature validation bypass ({mutations}) -- full SSO authentication bypass",
            "severity": "critical",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
