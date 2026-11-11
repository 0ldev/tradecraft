from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.actuator_probe import execute as actuator_execute
from tradecraft.adapters.actuator_probe import parse as actuator_parse
from tradecraft.tools.base import Tool


class ActuatorProbe(Tool):
    tool_id = "actuator_probe"

    def run(self, target: str, timeout: int = 8) -> Dict[str, Any]:
        raw = actuator_execute.execute(target=target, timeout=timeout)
        return actuator_parse.parse_actuator_result(raw)
