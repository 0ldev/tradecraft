"""
destructive: true -- see config/tools/ticketer.yaml and docs/policy.md.
This file implements no gating itself; the contract's declaration is
what the existing --allow-destructive mechanism reads.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.ticketer import execute as ticketer_execute
from tradecraft.adapters.ticketer import parse as ticketer_parse
from tradecraft.tools.base import Tool


class Ticketer(Tool):
    tool_id = "ticketer"

    def run(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        hash_type: str = "ntlm",
        username: str = "",
    ) -> Dict[str, Any]:
        raw = ticketer_execute.execute(
            domain=domain,
            krbtgt_hash=krbtgt_hash,
            domain_sid=domain_sid,
            hash_type=hash_type,
            username=username,
        )
        return ticketer_parse.parse_ticketer_result(raw)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # No network host/port to key a fact on -- ticketer has no
        # network target at all (scope_param is `domain`, not `target`).
        return []
