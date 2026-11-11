from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.teamcity_auth_bypass_probe import execute as teamcity_execute
from tradecraft.adapters.teamcity_auth_bypass_probe import parse as teamcity_parse
from tradecraft.tools.base import Tool


class TeamCityAuthBypassProbe(Tool):
    tool_id = "teamcity_auth_bypass_probe"

    def run(
        self,
        target: str,
        custom_port: Optional[int] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = teamcity_execute.execute(
            target=target,
            custom_port=custom_port,
            timeout=timeout,
        )
        return teamcity_parse.parse_teamcity_result(raw)
