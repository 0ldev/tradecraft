from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import tradecraft.adapters.ai_stack_probe.execute as probe_execute
import tradecraft.adapters.ai_stack_probe.parse as probe_parse
from tradecraft.tools.base import Tool


class AiStackProbe(Tool):
    tool_id = "ai_stack_probe"

    def run(
        self,
        target: str,
        service: str = "auto",
        port: Optional[int] = None,
        timeout: int = probe_execute.DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        raw = probe_execute.execute(
            target=target,
            service=service,
            port=port,
            timeout=timeout,
        )
        if raw.error:
            return {
                "target": target,
                "host": raw.host,
                "vulnerable": False,
                "findings": [],
                "count": 0,
                "unauthenticated_count": 0,
                "error": raw.error,
            }

        parsed = probe_parse.parse_probe_result(raw)
        res: Dict[str, Any] = {
            "target": target,
            "host": parsed["host"],
            "vulnerable": parsed["vulnerable"],
            "count": parsed["count"],
            "unauthenticated_count": parsed["unauthenticated_count"],
            "findings": parsed["findings"],
        }

        if parsed["findings"]:
            res["_full_evidence"] = {
                "target": target,
                "host": parsed["host"],
                "vulnerable": parsed["vulnerable"],
                "findings": parsed["findings"],
            }

        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        host = result.get("host")
        if not host:
            return []

        facts: List[Dict[str, Any]] = []
        for finding in result.get("findings", []):
            port = finding.get("port")
            if not port:
                continue
            service = finding.get("service")
            fact: Dict[str, Any] = {
                "host": host,
                "port": port,
                "service": service,
            }
            if finding.get("version"):
                fact["version"] = finding["version"]
            if finding.get("unauthenticated"):
                fact["ai_unauthenticated"] = True
            facts.append(fact)
        return facts
