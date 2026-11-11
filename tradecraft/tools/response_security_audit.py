"""
Replaces the former cookie_security_check, security_header_check, and
sri_check tools -- all three fetched the same URL independently for
different attributes of the same response; this does one fetch and runs
all three audits against it.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.response_security_audit import execute as audit_execute
from tradecraft.adapters.response_security_audit import parse as audit_parse
from tradecraft.tools.base import Tool

# SRI findings list is capped the same way sri_check's own tool layer
# capped it, to conserve context on a page with many cross-origin assets.
SRI_DISPLAY_CAP = 15


class ResponseSecurityAudit(Tool):
    tool_id = "response_security_audit"

    def run(self, target: str) -> Dict[str, Any]:
        raw = audit_execute.execute(target)
        if raw.error:
            # No response was obtained at all: report the failure, never a
            # result that looks like "cookies: 0, headers: all missing".
            return {
                "target": target,
                "final_url": raw.final_url or target,
                "error": raw.error,
            }

        result = audit_parse.parse(raw)
        result["target"] = target
        result["_full_evidence"] = dict(result)

        flagged = result.get("sri_cross_origin_missing_integrity", [])
        if len(flagged) > SRI_DISPLAY_CAP:
            result["sri_cross_origin_missing_integrity"] = flagged[:SRI_DISPLAY_CAP]
            result["sri_omitted_assets"] = len(flagged) - SRI_DISPLAY_CAP
            result["sri_note"] = (
                f"{len(flagged) - SRI_DISPLAY_CAP} more cross-origin assets missing SRI omitted to "
                "conserve context. Use read_evidence to inspect all."
            )

        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = urllib.parse.urlparse(result.get("final_url") or target).hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result:
            return []

        target_str = result.get("final_url") or params.get("target", "")
        parsed_url = urllib.parse.urlparse(target_str)
        host = parsed_url.hostname or target_str.split("/")[0].split(":")[0]
        if not host:
            return []
        evidence_id = result.get("evidence_id")

        facts: List[Dict[str, Any]] = []

        # --- cookies (same logic as the former cookie_security_check) ---
        # Missing flags are reported for every cookie, not only ones whose
        # name matches a known session-cookie marker -- a real admin-panel
        # session cookie (CA_PIN_ADMIN) matched none of those markers and
        # would otherwise never become a Fact despite having neither Secure
        # nor HttpOnly set. is_session_cookie still drives the severity
        # label since a name match is a reasonable (if imperfect) signal of
        # how sensitive the cookie actually is.
        for c in result.get("cookies", []):
            issues = c.get("issues")
            if not issues:
                continue
            is_session = c.get("is_session_cookie")
            label = "Session cookie" if is_session else "Cookie"
            f: Dict[str, Any] = {
                "host": host,
                "port": 443,
                "vulnerability": f"{label} '{c['name']}' missing security flags: {', '.join(issues)}",
                "severity": "medium" if is_session else "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        # --- headers (same logic as the former security_header_check) ---
        if result.get("missing_headers") or result.get("weak_headers"):
            header_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            parts: List[str] = []
            if result.get("missing_headers"):
                parts.append("missing " + ", ".join(result["missing_headers"]))
            for w in result.get("weak_headers", []):
                parts.append(f"{w['header']}: {'; '.join(w['issues'])}")
            f = {
                "host": host,
                "port": header_port,
                "vulnerability": "Weak or missing HTTP security headers: " + " | ".join(parts),
                "severity": "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        # --- SRI (same logic as the former sri_check) ---
        sri_count = result.get("sri_cross_origin_missing_integrity_count", 0)
        if sri_count:
            f = {
                "host": host,
                "port": 443,
                "vulnerability": f"{sri_count} cross-origin script(s)/stylesheet(s) loaded without Subresource Integrity",
                "severity": "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        return facts
