from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.magento_cosmicsting_probe import execute as cosmicsting_execute
from tradecraft.adapters.magento_cosmicsting_probe import parse as cosmicsting_parse
from tradecraft.tools.base import Tool


class MagentoCosmicStingProbe(Tool):
    tool_id = "magento_cosmicsting_probe"

    def run(
        self,
        target: str,
        callback_url: Optional[str] = None,
        cart_id: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = cosmicsting_execute.execute(
            target=target,
            callback_url=callback_url,
            cart_id=cart_id,
            timeout=timeout,
        )
        return cosmicsting_parse.parse_cosmicsting_result(raw)
