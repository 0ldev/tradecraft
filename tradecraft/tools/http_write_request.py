"""
Destructive: true -- this tool performs PUT/DELETE/PATCH, which can create
or remove real state on the target that doesn't undo itself. It is the
state-mutating counterpart split out of http_request (tradecraft/tools/
http_request.py), which only ever issues GET/HEAD/OPTIONS/POST. Unlike
http_request, there is no comma-batch mode here: a write against several
resources in one call is a larger, less deliberate blast radius than
batching idempotent reads, so each destructive write is always its own
single-URL call.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.http_write_request.execute import (
    DEFAULT_TIMEOUT,
    execute as run_http_write_request,
)
from tradecraft.adapters.http_write_request.parse import (
    DEFAULT_MAX_BODY_CHARS,
    evidence_target_from_url,
    host_port_from_url,
    parse_http_response,
)
from tradecraft.tools.base import Tool

# Hard per-call ceiling on how much body a single response can return --
# same cap as http_request, so this tool can't flood the context any more
# than the non-destructive one can.
MAX_BODY_CHARS_CAP = 8000


class HttpWriteRequest(Tool):
    tool_id = "http_write_request"

    def run(
        self,
        url: str,
        method: str,
        headers: Optional[str] = None,
        data: Optional[str] = None,
        follow_redirects: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
        body_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> Dict[str, Any]:
        raw = run_http_write_request(
            url=url,
            method=method,
            headers=headers,
            data=data,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

        chunk = min(max(1, int(body_chars or DEFAULT_MAX_BODY_CHARS)), MAX_BODY_CHARS_CAP)
        parsed = parse_http_response(raw, max_body_chars=chunk)

        # Store complete untruncated evidence for EvidenceStore
        parsed["_full_evidence"] = {
            "url": parsed.get("url", url),
            "effective_url": parsed.get("effective_url", url),
            "method": parsed.get("method", method),
            "status_code": parsed.get("status_code", 0),
            "headers": parsed.get("headers", {}),
            "raw_body": raw.get("raw_body", ""),
            "duration_seconds": parsed.get("duration_seconds", 0.0),
        }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        url = params.get("url", "")
        full = result.pop("_full_evidence", None)
        if not url or full is None:
            return None
        canonical = evidence_target_from_url(url) or url
        return canonical, full, []

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = params.get("url", "")
        if not url:
            return []

        host, port = host_port_from_url(url)
        status_code = result.get("status_code", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}

        if status_code in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403):
            fact["live"] = True

        evidence_id = result.get("evidence_id")
        if evidence_id:
            fact["evidence"] = evidence_id

        if len(fact) > 2:
            return [fact]
        return []
