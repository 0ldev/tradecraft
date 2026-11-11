"""
Real linpeas.sh enumeration over SSH on a
host already reached via some other foothold. Classified as
destructive: false. Belongs to profile 'post-exploitation'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.linpeas import execute as lp_execute
from tradecraft.adapters.linpeas import parse as lp_parse
from tradecraft.tools.base import Tool


class Linpeas(Tool):
    tool_id = "linpeas"

    def is_available(self) -> bool:
        return lp_execute.find_sshpass_binary() is not None

    def run(self, target: str, ssh_user: str, ssh_pass: str) -> Dict[str, Any]:
        raw = lp_execute.execute(
            target=target, ssh_user=ssh_user, ssh_pass=ssh_pass
        )
        parsed = lp_parse.parse_linpeas_result(raw)

        if raw.stdout or raw.stderr:
            # The full transcript is the authoritative record; the
            # model-facing view is capped, so keep the complete
            # transcript as evidence.
            parsed["_full_evidence"] = {
                "target": raw.target,
                "raw_stdout": lp_parse.cap_evidence(raw.stdout),
                "raw_stderr": lp_parse.cap_evidence(raw.stderr),
            }

        return parsed

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = lp_parse.parse_host_port(target)
        return (host or target), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        if result.get("status") != "success":
            return []

        target = params.get("target", "")
        host, port = lp_parse.parse_host_port(target)
        if not host:
            return []

        fact: Dict[str, Any] = {
            "host": host,
            "port": port or 22,
            "protocol": "ssh",
            "linpeas_enumerated": True,
            "linpeas_finding_count": result.get("finding_count", 0),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
