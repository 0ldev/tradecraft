from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.idor_probe import execute as idor_execute
from tradecraft.adapters.idor_probe import parse as idor_parse
from tradecraft.tools.base import Tool


class IdorProbe(Tool):
    tool_id = "idor_probe"

    def run(
        self,
        target: str,
        param: Optional[str] = None,
        candidate_values: Optional[str] = None,
        headers: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = idor_execute.execute(
            target=target,
            param=param,
            candidate_values=candidate_values,
            headers=headers,
            timeout=timeout,
        )
        if raw.error:
            return {"target": target, "error": raw.error}

        parsed = idor_parse.parse_result(raw)

        # Store complete evidence outside prompt context
        parsed["_full_evidence"] = {
            "target": target,
            "param": raw.param,
            "baseline_id": raw.baseline_id,
            "baseline": {
                "url": raw.baseline_response.url if raw.baseline_response else "",
                "status_code": raw.baseline_response.status_code if raw.baseline_response else 0,
                "headers": raw.baseline_response.headers if raw.baseline_response else {},
                "body": raw.baseline_response.body if raw.baseline_response else "",
            },
            "probes": [
                {
                    "id": p.tested_id,
                    "url": p.url,
                    "status_code": p.status_code,
                    "headers": p.headers,
                    "body": p.body,
                }
                for p in raw.probes
            ],
        }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Facts require semantic validation by the model (log_finding / log_note)
        # to distinguish sensitive private object leaks from public catalog/blog records.
        return []
