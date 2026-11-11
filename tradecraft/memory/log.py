"""
Engagement memory: a plain, append-only log the model writes to in its
own words.

The whole point of this file is to be dumb. Structure-free text cannot be
"wrong" the way a mis-derived Hypothesis can be, and the loop's job is
just to hand it back to the model in full each turn, not to interpret it.
No timestamps -- the model never reasons about *when* something happened
within one engagement, only *what* and *why*, so a timestamp is pure
token cost with no decision-making value. If this ever needs retrieval/
pagination because engagements get long, that is a scaling problem to
solve later -- not a reason to reintroduce a graph up front for a model
that hasn't shown it needs one.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class LogEntry:
    kind: str  # "note" | "finding"
    text: str
    finding_id: Optional[int] = None  # set only for kind == "finding"
    retracted: bool = False
    evidence_id: Optional[str] = None  # tool evidence this finding rests on, if the model gave one
    evidence_verified: bool = True

    def source_tag(self) -> str:
        """Where a finding's claim comes from, as the model stated it. A
        finding with no evidence_id (or an evidence_id not found in
        EvidenceStore) is tagged rather than rejected: the model may
        legitimately log something a tool result doesn't cover, and the
        report should say so instead of presenting it as tool-backed."""
        if self.evidence_id:
            if not self.evidence_verified:
                return f"[unverified: unknown evidence_id {self.evidence_id}]"
            return f"[evidence: {self.evidence_id}]"
        return "[unverified: no evidence_id]"

    def render(self) -> str:
        if self.kind == "finding":
            tag = f"FINDING #{self.finding_id}"
            if self.retracted:
                tag += " [RETRACTED]"
            return f"{tag} {self.source_tag()}: {self.text}"
        return f"note: {self.text}"


class EngagementMemory:
    """In-process log for one engagement run. Optionally persisted to disk
    as plain text so a run can be inspected after the fact (no replay /
    structured-read support in v0 -- that's a feature to add once the log
    format has proven itself, not something to pre-build)."""

    def __init__(self, persist_path: str | None = None):
        self.entries: List[LogEntry] = []
        self._next_finding_id = 1
        self.persist_path = Path(persist_path) if persist_path else None
        if self.persist_path:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            self.persist_path.touch(exist_ok=True)

    def note(self, text: str) -> None:
        self._append(LogEntry(kind="note", text=text))

    def finding(
        self,
        text: str,
        evidence_id: Optional[str] = None,
        evidence_verified: bool = True,
    ) -> int:
        """Returns this finding's id, stable for the rest of the
        engagement -- the model can later pass it to retract() if the
        finding turns out to be wrong. evidence_id, when given, names the
        tool result the finding rests on."""
        finding_id = self._next_finding_id
        self._next_finding_id += 1
        clean_id = evidence_id or None
        self._append(LogEntry(
            kind="finding", text=text, finding_id=finding_id,
            evidence_id=clean_id,
            evidence_verified=(evidence_verified if clean_id else False),
        ))
        return finding_id

    def retract(self, finding_id: int, reason: str) -> bool:
        """Marks a previously-logged finding as superseded. A retracted
        finding is excluded from findings() (and therefore the report)
        but is never deleted -- it stays in the full rendered log,
        marked [RETRACTED], and a note recording why is appended.
        Returns False if no finding with that id exists, so the caller
        can tell the model its retraction didn't match anything rather
        than silently doing nothing."""
        for entry in self.entries:
            if entry.kind == "finding" and entry.finding_id == finding_id:
                entry.retracted = True
                self._append(LogEntry(kind="note", text=f"Finding #{finding_id} retracted: {reason}"))
                return True
        return False

    def _append(self, entry: LogEntry) -> None:
        self.entries.append(entry)
        if self.persist_path:
            with open(self.persist_path, "a") as f:
                f.write(entry.render() + "\n")

    def render(self) -> str:
        if not self.entries:
            return "(empty -- nothing logged yet)"
        return "\n".join(e.render() for e in self.entries)

    def findings(self) -> List[str]:
        return [f"{e.text} {e.source_tag()}" for e in self.entries if e.kind == "finding" and not e.retracted]
