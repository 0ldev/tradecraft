"""
Only non-mutating methods (GET/HEAD/OPTIONS/POST) are permitted.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.hpp_probe import execute as hpp_execute
from tradecraft.adapters.hpp_probe import parse as hpp_parse
from tradecraft.tools.base import Tool


class HppProbe(Tool):
    tool_id = "hpp_probe"

    def run(
        self,
        target: str,
        method: str = "GET",
        params: Optional[str] = None,
        body: Optional[str] = None,
        headers: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = hpp_execute.execute(
            target=target,
            method=method,
            params=params,
            body=body,
            headers=headers,
            timeout=timeout,
        )
        result = hpp_parse.parse(raw)
        if result.get("hpp_observed"):
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
        # HPP is a technique, not a vulnerability by itself; the model decides
        # whether an observed behavior is exploitable in the target's context.
        return []
