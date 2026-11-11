from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.cewl import execute as cewl_execute
from tradecraft.adapters.cewl import parse as cewl_parse
from tradecraft.tools.base import Tool


class Cewl(Tool):
    tool_id = "cewl"

    def is_available(self) -> bool:
        return cewl_execute.is_available()

    def run(
        self,
        target: str,
        depth: int = 2,
        min_word_length: int = 3,
        max_words: int = cewl_execute.MAX_WORDS,
    ) -> Dict[str, Any]:
        raw = cewl_execute.execute(
            target=target,
            depth=depth,
            min_word_length=min_word_length,
            max_words=max_words,
        )
        return cewl_parse.parse_cewl_result(raw, target)
