"""
Non-destructive: lists tags only, never pulls a manifest or layer.
Belongs to profile 'cloud'. Its output is the input for trivy_scan.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.registry_tag_enum import execute as rte_execute
from tradecraft.adapters.registry_tag_enum import parse as rte_parse
from tradecraft.tools.base import Tool


class RegistryTagEnum(Tool):
    tool_id = "registry_tag_enum"

    def run(self, repository: str, registry: str = "", timeout: int = 10) -> Dict[str, Any]:
        raw = rte_execute.execute(repository=repository, registry=registry, timeout=timeout)
        return rte_parse.parse_registry_tag_result(raw)
