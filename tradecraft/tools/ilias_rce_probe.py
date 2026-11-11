from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.ilias_rce_probe import execute as ilias_execute
from tradecraft.adapters.ilias_rce_probe import parse as ilias_parse
from tradecraft.tools.base import Tool


class IliasRceProbe(Tool):
    tool_id = "ilias_rce_probe"

    def run(
        self,
        target: str,
        host_header: Optional[str] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = ilias_execute.execute(
            target=target,
            host_header=host_header,
            timeout=timeout,
        )
        return ilias_parse.parse_ilias_result(raw)
