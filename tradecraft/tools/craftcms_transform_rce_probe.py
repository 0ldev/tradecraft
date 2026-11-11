from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.craftcms_transform_rce_probe import execute as craft_execute
from tradecraft.adapters.craftcms_transform_rce_probe import parse as craft_parse
from tradecraft.tools.base import Tool


class CraftcmsTransformRceProbe(Tool):
    tool_id = "craftcms_transform_rce_probe"

    def run(
        self,
        target: str,
        host_header: Optional[str] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = craft_execute.execute(
            target=target,
            host_header=host_header,
            timeout=timeout,
        )
        return craft_parse.parse_craft_result(raw)
