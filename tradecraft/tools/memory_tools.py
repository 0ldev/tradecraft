"""
The two tools that write into the engagement log (`tradecraft/memory/log.py`).
Unlike `nmap_scan`, these are bound to a specific `EngagementMemory`
instance at construction time, since where they write depends on which
run is in progress -- they're built per-run in `execution/loop.py`, not
listed in the static `registry.ALL_TOOLS` catalog.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.memory.cross_engagement import CrossEngagementMemory
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.base import Tool


class LogNote(Tool):
    tool_id = "log_note"

    def __init__(self, memory: EngagementMemory):
        self.memory = memory

    def run(self, text: str) -> Dict[str, Any]:
        self.memory.note(text)
        return {"logged": True}


class LogFinding(Tool):
    tool_id = "log_finding"

    def __init__(
        self,
        memory: EngagementMemory,
        evidence: Optional[EvidenceStore] = None,
    ):
        self.memory = memory
        self.evidence = evidence

    def run(self, text: str, evidence_id: Optional[str] = None) -> Dict[str, Any]:
        clean_id = (evidence_id or "").strip() or None
        if clean_id and self.evidence is not None and not self.evidence.has_evidence(clean_id):
            finding_id = self.memory.finding(
                text, evidence_id=clean_id, evidence_verified=False,
            )
            return {
                "logged": True,
                "finding_id": finding_id,
                "verified_evidence": False,
                "warning": (
                    f"evidence_id '{clean_id}' was not found in EvidenceStore; "
                    f"finding #{finding_id} was logged as unverified. Pass an "
                    "evidence_id returned by a tool call in this run, or call "
                    "retract_finding if this claim is not backed by tool evidence."
                ),
            }
        finding_id = self.memory.finding(text, evidence_id=clean_id)
        return {"logged": True, "finding_id": finding_id}


class RetractFinding(Tool):
    tool_id = "retract_finding"

    def __init__(self, memory: EngagementMemory):
        self.memory = memory

    def run(self, finding_id: int, reason: str) -> Dict[str, Any]:
        retracted = self.memory.retract(finding_id, reason)
        if not retracted:
            return {"retracted": False, "error": f"no finding with finding_id {finding_id} exists"}
        return {"retracted": True, "finding_id": finding_id}


class RecallMemory(Tool):
    tool_id = "recall_memory"

    def __init__(
        self,
        store: Optional[CrossEngagementMemory] = None,
        current_run_id: Optional[str] = None,
    ):
        self.store = store if store is not None else CrossEngagementMemory(db_path=":memory:")
        self.current_run_id = current_run_id

    def run(
        self,
        query: str,
        target: str = "",
        kind: str = "",
        limit: int = 10,
    ) -> Dict[str, Any]:
        clean_kind = (kind or "").strip().lower()
        if clean_kind and clean_kind not in ("finding", "fact", "note"):
            return {
                "error": f"invalid kind '{kind}' -- allowed: 'finding', 'fact', 'note'",
            }
        records = self.store.search(
            query=query,
            target=target if target else None,
            kind=clean_kind if clean_kind else None,
            limit=limit,
            exclude_run_id=self.current_run_id,
        )
        return {
            "query": query,
            "match_count": len(records),
            "matches": [r.to_dict() for r in records],
        }
