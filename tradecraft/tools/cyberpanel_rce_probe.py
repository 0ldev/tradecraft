from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.cyberpanel_rce_probe import execute as cyberpanel_execute
from tradecraft.adapters.cyberpanel_rce_probe import parse as cyberpanel_parse
from tradecraft.tools.base import Tool


class CyberPanelRceProbe(Tool):
    tool_id = "cyberpanel_rce_probe"

    def run(
        self,
        target: str,
        custom_port: Optional[int] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = cyberpanel_execute.execute(
            target=target,
            custom_port=custom_port,
            timeout=timeout,
        )
        return cyberpanel_parse.parse_cyberpanel_result(raw)
