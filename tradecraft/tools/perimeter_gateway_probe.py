from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.perimeter_gateway_probe import execute as perimeter_execute
from tradecraft.adapters.perimeter_gateway_probe import parse as perimeter_parse
from tradecraft.tools.base import Tool


class PerimeterGatewayProbe(Tool):
    tool_id = "perimeter_gateway_probe"

    def run(
        self,
        target: str,
        appliance: Optional[str] = "all",
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = perimeter_execute.execute(
            target=target,
            appliance=appliance,
            timeout=timeout,
        )
        return perimeter_parse.parse_perimeter_result(raw)
