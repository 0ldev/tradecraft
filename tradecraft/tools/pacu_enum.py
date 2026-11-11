"""
Read-only AWS enumeration via Pacu, using
an access key already obtained some other way (trufflehog, a
metadata-endpoint probe, etc). Classified as destructive: false --
every action only reads. Belongs to profile 'cloud'.

A credentialed privilege-escalation *attempt* (iam__privesc_scan without
--scan-only) and a real S3 download belong in a separate, destructive: true
pacu_exploit tool -- not here, per this codebase's mode-split convention
for one binary with both enumeration and exploitation sub-commands (see
also netexec_enum/netexec_exploit, certipy_enum).
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cloudenum.parse import host_port_from_target
from tradecraft.adapters.pacu_enum import execute as pacu_execute
from tradecraft.adapters.pacu_enum import parse as pacu_parse
from tradecraft.tools.base import Tool


class PacuEnum(Tool):
    tool_id = "pacu_enum"

    def is_available(self) -> bool:
        return pacu_execute.is_available()

    def run(self, target: str, action: str, credential: str) -> Dict[str, Any]:
        raw = pacu_execute.execute(target=target, action=action, credential=credential)
        result = pacu_parse.parse_pacu_enum_result(raw)

        combined = pacu_parse.redact_credentials(
            f"{raw.stdout or ''}\n{raw.stderr or ''}".strip(), credential
        )
        if combined.strip():
            result["_full_evidence"] = {
                "target": target,
                "action": action,
                "session": raw.session,
                "transcript": pacu_parse.cap_evidence(combined),
            }
        return result

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("status") != "success":
            return []

        host, port = host_port_from_target(target)
        fact: Dict[str, Any] = {"host": host, "port": port}
        action = result.get("action")

        if action == "enum_permissions":
            fact["aws_iam_enum_tested"] = True
            confirmed = result.get("users_confirmed", 0) + result.get("roles_confirmed", 0)
            if confirmed:
                fact["aws_iam_subjects_confirmed"] = confirmed
        elif action == "privesc_scan":
            fact["aws_privesc_tested"] = True
            if result.get("already_admin"):
                fact["aws_privesc_already_admin"] = True
            methods = result.get("confirmed_methods") or []
            if methods:
                fact["aws_privesc_confirmed_methods"] = len(methods)
        elif action == "s3_list":
            fact["aws_s3_enum_tested"] = True
            if result.get("readable_buckets"):
                fact["aws_s3_buckets_readable"] = result["readable_buckets"]

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
