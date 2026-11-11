from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.xxe_probe import execute as xxe_execute
from tradecraft.adapters.xxe_probe import parse as xxe_parse
from tradecraft.tools.base import Tool


class XxeProbe(Tool):
    tool_id = "xxe_probe"

    def run(
        self,
        target: str,
        oob_domain: str,
        content_type: str = "application/xml",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = xxe_execute.execute(
            target=target,
            oob_domain=oob_domain,
            content_type=content_type,
            timeout=timeout,
        )
        return xxe_parse.parse_xxe_result(raw)
