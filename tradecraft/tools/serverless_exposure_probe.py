from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.serverless_exposure_probe import execute as sep_execute
from tradecraft.adapters.serverless_exposure_probe import parse as sep_parse
from tradecraft.tools.base import Tool


class ServerlessExposureProbe(Tool):
    tool_id = "serverless_exposure_probe"

    def run(
        self,
        provider: str,
        candidates: str,
        function_names: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = sep_execute.execute(provider=provider, candidates=candidates, function_names=function_names, timeout=timeout)
        if raw.error:
            return {"provider": provider, "error": raw.error}

        result = sep_parse.parse(raw)
        result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        candidates = params.get("candidates", "")
        if not candidates or full is None:
            return None
        first = candidates.split(",")[0].strip()
        return first or "serverless_exposure_probe", full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result:
            return []
        evidence_id = result.get("evidence_id")
        facts: List[Dict[str, Any]] = []
        for entry in result.get("results", []):
            if entry.get("classification") != "exposed":
                continue
            parsed = urllib.parse.urlsplit(entry.get("url", ""))
            host = parsed.hostname
            if not host:
                continue
            severity = "high" if entry.get("leaked_secrets") else "medium"
            vuln = f"Unauthenticated serverless function exposed at {entry['url']}"
            if entry.get("leaked_secrets"):
                vuln += f" -- {len(entry['leaked_secrets'])} leaked secret(s) found in response body"
            fact: Dict[str, Any] = {
                "host": host,
                "port": 443,
                "vulnerability": vuln,
                "severity": severity,
            }
            if evidence_id:
                fact["evidence"] = evidence_id
            facts.append(fact)
        return facts
