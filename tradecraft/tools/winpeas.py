"""
Real winPEASany.exe enumeration via
Impacket's wmiexec.py, requiring already-obtained domain credentials.
Classified as destructive: false. Belongs to profiles 'ad-network' and
'post-exploitation'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.winpeas import execute as wp_execute
from tradecraft.adapters.winpeas import parse as wp_parse
from tradecraft.tools.base import Tool

# wmiexec.py runs over DCOM/WMI, whose endpoint-mapper port is the fixed
# RPC port; the dynamic high port it negotiates isn't a stable fact.
_WMI_PORT = 135


class Winpeas(Tool):
    tool_id = "winpeas"

    def is_available(self) -> bool:
        return wp_execute.find_wmiexec_binary() is not None

    def run(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
    ) -> Dict[str, Any]:
        raw = wp_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
        )
        parsed = wp_parse.parse_winpeas_result(raw)

        if raw.stdout or raw.stderr:
            # The full transcript is the authoritative record; the
            # model-facing view is capped, so keep the complete
            # transcript as evidence. Operator-supplied secrets never
            # appear in wmiexec.py's own stdout/stderr, so no redaction
            # is needed here (unlike netexec_exploit's recovered hashes).
            parsed["_full_evidence"] = {
                "target": raw.target,
                "domain": raw.domain,
                "raw_stdout": wp_parse.cap_evidence(raw.stdout),
                "raw_stderr": wp_parse.cap_evidence(raw.stderr),
            }

        return parsed

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = wp_parse.normalize_target_host(target)
        return (host or target), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        if result.get("status") != "success":
            return []

        target = params.get("target", "")
        host = wp_parse.normalize_target_host(target)
        if not host:
            return []

        fact: Dict[str, Any] = {
            "host": host,
            "port": _WMI_PORT,
            "protocol": "wmi",
            "winpeas_enumerated": True,
            "winpeas_finding_count": result.get("finding_count", 0),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
