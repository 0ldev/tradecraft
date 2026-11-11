from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cloudfox import execute as cf_execute
from tradecraft.adapters.cloudfox import parse as cf_parse
from tradecraft.tools.base import Tool


class Cloudfox(Tool):
    tool_id = "cloudfox"

    def is_available(self) -> bool:
        return cf_execute.find_binary() is not None

    def run(
        self,
        provider: str = "aws",
        command: str = "permissions",
        target: str = "",
        credentials: str = "",
    ) -> Dict[str, Any]:
        raw = cf_execute.execute(
            provider=provider,
            command=command,
            target=target,
            credentials=credentials,
        )
        parsed = cf_parse.parse_cloudfox_output(raw)
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "provider": provider,
                "command": command,
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
                "json_data": raw.json_data,
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target") or result.get("provider", "cloud")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target") or result.get("provider", "cloud")
        if not result.get("findings_count"):
            return []
        return [
            {
                "host": target,
                "port": 443,
                "cloud_attack_paths_found": True,
                "cloudfox_findings_count": result.get("findings_count", 0),
            }
        ]
