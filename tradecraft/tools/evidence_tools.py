"""
Evidence tools: ReadEvidence and SearchEvidence.
Glues the EvidenceStore with model-facing YAML contracts config/tools/read_evidence.yaml
and config/tools/search_evidence.yaml.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.tools.base import Tool


class ReadEvidence(Tool):
    tool_id = "read_evidence"

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def run(self, target: str, tool_id: str) -> Dict[str, Any]:
        from tradecraft.tools.registry import ALL_TOOLS
        valid_tools = {t.tool_id for t in ALL_TOOLS}
        if tool_id not in valid_tools:
            return {"error": f"unknown tool '{tool_id}' -- allowed: {sorted(valid_tools)}"}
        return self._store.read(target=target, tool_id=tool_id)


class SearchEvidence(Tool):
    tool_id = "search_evidence"

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def run(self, query: str, target: str = "") -> Dict[str, Any]:
        return self._store.search(query=query, target=target if target else None)
