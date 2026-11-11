from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.coercer import execute as coercer_execute
from tradecraft.adapters.coercer import parse as coercer_parse
from tradecraft.tools.base import Tool


class Coercer(Tool):
    tool_id = "coercer"

    def is_available(self) -> bool:
        return coercer_execute.find_binary() is not None

    def run(
        self,
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        hashes: str = "",
    ) -> Dict[str, Any]:
        raw = coercer_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
        )
        parsed = coercer_parse.parse_coercer_output(raw)
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "target": target,
                "domain": domain,
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target") or result.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target") or result.get("target", "")
        if not target or not result.get("vulnerable"):
            return []
        return [
            {
                "host": target,
                "port": 445,
                "coercion_vulnerable": True,
                "coercible_methods": result.get("coercible_methods", []),
            }
        ]
