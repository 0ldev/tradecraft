"""
Gowitness tool: saves a screenshot of a target URL to evidence storage.
Glues config/tools/gowitness.yaml to tradecraft.adapters.gowitness.execute.
"""
from __future__ import annotations

import hashlib
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.gowitness import execute as gowitness_execute
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.tools.base import Tool


def _host_port_from_target(target: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


class Gowitness(Tool):
    tool_id = "gowitness"

    def __init__(self, store: Optional[EvidenceStore] = None) -> None:
        self._store = store

    def run(self, target: str) -> Dict[str, Any]:
        raw = gowitness_execute.execute(target)
        if raw.error:
            return {"target": target, "error": raw.error}

        store = self._store if self._store is not None else EvidenceStore()
        key = store.save_binary(target=target, tool_id=self.tool_id, data=raw.png_bytes)
        sha = hashlib.sha256(raw.png_bytes).hexdigest()
        return {
            "target": target,
            "evidence_id": key,
            "sha256": sha,
            "bytes_captured": len(raw.png_bytes),
            "note": "screenshot saved to evidence storage; not viewable by you",
        }

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> None:
        # Binary evidence is already saved directly by run() via store.save_binary()
        return None

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        evidence_id = result.get("evidence_id")
        if not target or not evidence_id:
            return []
        host, port = _host_port_from_target(target)
        return [{"host": host, "port": port, "screenshot": evidence_id}]
