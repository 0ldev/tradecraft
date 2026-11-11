from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.acl_bypass_probe import execute as acl_execute
from tradecraft.adapters.acl_bypass_probe import parse as acl_parse
from tradecraft.tools.base import Tool


class AclBypassProbe(Tool):
    tool_id = "acl_bypass_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = acl_execute.execute(target=target, timeout=timeout)
        return acl_parse.parse_acl_bypass_result(raw)
