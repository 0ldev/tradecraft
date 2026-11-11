from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.jenkins_unauth_probe.execute import execute as jenkins_execute
from tradecraft.adapters.jenkins_unauth_probe.parse import parse as jenkins_parse
from tradecraft.tools.base import Tool


class JenkinsUnauthProbe(Tool):
    tool_id = "jenkins_unauth_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = jenkins_execute(target=target, timeout=timeout)
        parsed = jenkins_parse(raw)

        parsed["_full_evidence"] = {
            "target": raw.target,
            "base_url": raw.base_url,
            "whoami_body": raw.whoami_body,
            "api_json": raw.api_json,
        }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        host = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("is_jenkins"):
            return []

        fact: Dict[str, Any] = {
            "host": params.get("target", ""),
            "port": 443,
            "service": "jenkins",
            "state": "open",
        }
        if result.get("jenkins_version"):
            fact["version"] = result["jenkins_version"]
        if result.get("script_console_reachable"):
            fact["vulnerability"] = "Unauthenticated Jenkins Script Console (RCE-capable)"
            fact["severity"] = "critical"
        elif result.get("manage_panel_reachable"):
            fact["vulnerability"] = "Unauthenticated Jenkins admin panel access"
            fact["severity"] = "high"
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
