"""
Detection-only -- never creates a notebook or executes code.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.jupyter_exposure_probe import execute as jupyter_execute
from tradecraft.adapters.jupyter_exposure_probe import parse as jupyter_parse
from tradecraft.tools.base import Tool


class JupyterExposureProbe(Tool):
    tool_id = "jupyter_exposure_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = jupyter_execute.execute(target=target, timeout=timeout)
        result = jupyter_parse.parse(raw)
        if result.get("vulnerable"):
            result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        host = result.get("host") or params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        host = result.get("host") or params.get("target", "")
        if not host:
            return []
        service = result.get("service") or "jupyter"
        fact: Dict[str, Any] = {
            "host": host,
            "port": result.get("port") or 8888,
            "service": service,
            "state": "open",
            "vulnerability": f"Unauthenticated {service} API access (notebook code execution)",
            "severity": "critical",
        }
        if result.get("version"):
            fact["version"] = result["version"]
        evidence_id = result.get("evidence_id")
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
