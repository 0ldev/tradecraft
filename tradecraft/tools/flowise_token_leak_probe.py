from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.flowise_token_leak_probe import execute as flowise_execute
from tradecraft.adapters.flowise_token_leak_probe import parse as flowise_parse
from tradecraft.tools.base import Tool


class FlowiseTokenLeakProbe(Tool):
    tool_id = "flowise_token_leak_probe"

    def run(
        self,
        target: str,
        email: str = "admin@local",
        host_header: Optional[str] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        raw = flowise_execute.execute(
            target=target,
            email=email,
            host_header=host_header,
            timeout=timeout,
        )
        return flowise_parse.parse_flowise_result(raw)
