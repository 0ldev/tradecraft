"""Finding verification (Tradecraft 2.0, Phase 2).

A finding is only as good as the evidence under it. This module adds a
deterministic verification layer over what already exists -- the
`evidence_id` each logged finding carries and the EvidenceStore it
points at -- instead of inventing a parallel truth source:

- **verified**        -- the finding cites an evidence_id that resolves to
  real, non-empty stored evidence.
- **unverified**      -- the model logged a finding with no evidence_id
  at all. Not wrong, but the report must say so (it already tags these
  in the log render; this module makes the same fact queryable).
- **missing_evidence**-- the finding cites an evidence_id that doesn't
  resolve in the store. The log marks this inline
  (`[unverified: unknown evidence_id ...]`); here it's a first-class
  status so the model gets a targeted, actionable error instead of
  discovering it at report time.

Plus one model-facing tool, `verify_finding`: given a finding id, it
loads the actual evidence and hands the model a compact digest, so a
claim can be confirmed or retracted mid-engagement rather than at
report time. This is the cheap half of a full replay engine: the
evidence is already on disk; here it finally gets *consulted*.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.base import Tool

VERIFIED = "verified"
UNVERIFIED = "unverified"
MISSING_EVIDENCE = "missing_evidence"

STATUS_LABEL = {
    VERIFIED: "VERIFIED",
    UNVERIFIED: "UNVERIFIED (no evidence cited)",
    MISSING_EVIDENCE: "UNVERIFIED (cited evidence not found)",
}


def classify_findings(memory: EngagementMemory, evidence: EvidenceStore) -> List[Dict[str, Any]]:
    """One record per non-retracted finding, with a deterministic
    verification status derived from the EvidenceStore -- never from
    model assertion."""
    out: List[Dict[str, Any]] = []
    for entry in memory.entries:
        if entry.kind != "finding" or entry.retracted:
            continue
        if not entry.evidence_id:
            status = UNVERIFIED
        elif evidence.has_evidence(entry.evidence_id):
            status = VERIFIED
        else:
            status = MISSING_EVIDENCE
        out.append({
            "finding_id": entry.finding_id,
            "text": entry.text,
            "evidence_id": entry.evidence_id,
            "status": status,
        })
    return out


def render_verification_summary(
    classified: List[Dict[str, Any]],
) -> str:
    """Compact per-turn render for the state message: which logged
    findings are standing on real evidence and which aren't. The model
    can't fix what it can't see, and report time is too late."""
    if not classified:
        return "(no findings logged yet)"
    lines = []
    for f in classified:
        ev = f["evidence_id"] or "-"
        lines.append(f"#{f['finding_id']} [{STATUS_LABEL[f['status']]}] evidence={ev}")
    return "\n".join(lines)


def _digest(data: Any, limit: int = 2000) -> str:
    """Compact, readable digest of stored evidence for the model."""
    try:
        text = json.dumps(data, default=str, indent=1)
    except (TypeError, ValueError):
        text = str(data)
    if len(text) > limit:
        text = text[:limit] + f"\n... (truncated at {limit} chars; full evidence on disk)"
    return text


class VerifyFinding(Tool):
    """Loads the evidence a finding cites and returns a compact digest.
    Bound per-run to the memory + evidence stores (same pattern as
    LogFinding) -- built in execution/loop.py, not in the registry."""

    tool_id = "verify_finding"

    def __init__(self, memory: EngagementMemory, evidence: EvidenceStore):
        self.memory = memory
        self.evidence = evidence

    def run(self, finding_id: int) -> Dict[str, Any]:
        entry = next(
            (
                e for e in self.memory.entries
                if e.kind == "finding" and e.finding_id == finding_id
            ),
            None,
        )
        if entry is None:
            return {"error": f"no finding #{finding_id} exists in this engagement"}
        if entry.retracted:
            return {"error": f"finding #{finding_id} is retracted -- nothing to verify"}

        if not entry.evidence_id:
            return {
                "finding_id": finding_id,
                "status": UNVERIFIED,
                "note": (
                    "this finding cites no evidence_id. To verify it, re-run the "
                    "underlying tool, then log_finding again with the new evidence_id "
                    "(or retract_finding it if you can't back it)."
                ),
            }

        tool_id, _, target = entry.evidence_id.partition(":")
        data = self.evidence.read(target=target.strip(), tool_id=tool_id.strip())
        if "error" in data:
            return {
                "finding_id": finding_id,
                "status": MISSING_EVIDENCE,
                "evidence_id": entry.evidence_id,
                "error": (
                    f"cited evidence '{entry.evidence_id}' does not resolve in the "
                    "evidence store. Re-run the underlying tool to regenerate it, or "
                    "retract_finding this claim."
                ),
            }

        return {
            "finding_id": finding_id,
            "status": VERIFIED,
            "evidence_id": entry.evidence_id,
            "evidence_digest": _digest(data),
            "note": (
                "This is the raw evidence your finding rests on. Confirm the finding's "
                "text matches it (log a correcting note if it doesn't), or retract the "
                "finding if the evidence doesn't actually support it."
            ),
        }
