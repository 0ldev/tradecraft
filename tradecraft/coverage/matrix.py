"""Coverage Matrix (Tradecraft 2.0, Phase 0).

One deterministic, queryable view over the FactStore answering a single
question: **which attack-surface element has been checked for which
vulnerability class, and what came of it?**

The matrix is pure -- it reads (host, port) fact records and derives
cell statuses from the field-name conventions tools already report
(`sqli_tested`, `sqli_injectable`, `xss_vulnerable`, ...). It never
trusts model assertions: the same rule that governs FactStore ("a fact
is written mechanically from a tool's parsed result") governs the
matrix, because the matrix is just a different projection of the same
facts.

Three consumers, one source of truth:

1. The model -- via `render_compact()`, a token-cheap table appended to
   the per-turn state message. Far denser than raw FACTS lines: the
   model sees coverage gaps at a glance instead of re-deriving them
   from full field dumps, which is exactly the "decide what to run
   next" question it faces every turn.
2. The Studio UI (tradecraft/studio/) -- via `to_dict()`.
3. The report generator -- coverage stats rendered deterministically.

Statuses per (target, class) cell:

- "vulnerable"  -- some tool reported the class vulnerable/injectable
- "clean"       -- some tool reported the class tested, none vulnerable
- "untested"    -- the target exists but no field for the class appears
- "partial"     -- parameters were discovered (arjun_params_discovered /
                   params_discovered) but the injection-class fields are
                   all absent -- the model found attack surface but
                   never followed through. This is the nudge the old
                   hardcoded _has_open_injection_thread heuristic made,
                   now generalized and visible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

# Classes with a human display name, in stable display order. The scan
# itself is generic (any <prefix>_tested / <prefix>_vulnerable /
# <prefix>_injectable triple), so a future tool that reports a new
# class appears automatically; this dict only controls ordering and
# naming for the classes known today.
KNOWN_CLASSES: List[Tuple[str, str]] = [
    ("sqli", "SQLi"),
    ("xss", "XSS"),
    ("cmdi", "CmdInj"),
    ("ssrf", "SSRF"),
    ("open_redirect", "OpenRedir"),
    ("nosql", "NoSQLi"),
    ("crlf", "CRLF"),
    ("lfi", "LFI"),
    ("rce", "RCE"),
]

VULNERABLE_SUFFIXES = ("_vulnerable", "_injectable")
TESTED_SUFFIX = "_tested"

STATUS_VULNERABLE = "vulnerable"
STATUS_CLEAN = "clean"
STATUS_PARTIAL = "partial"
STATUS_UNTESTED = "untested"

# Short forms for the compact model-facing render. Deliberately terse:
# this table is re-sent every turn, so every token here is a token the
# engagement pays forever.
_STATUS_SHORT = {
    STATUS_VULNERABLE: "VULN",
    STATUS_CLEAN: "clean",
    STATUS_PARTIAL: "part!",
    STATUS_UNTESTED: "-",
}


def _classes_in_record(record: Dict[str, Any]) -> Dict[str, str]:
    """Derive per-class statuses from one (host, port) record by scanning
    its field names. Generic: any field ending in _tested / _vulnerable /
    _injectable contributes, known or not."""
    statuses: Dict[str, str] = {}
    for key, value in record.items():
        if key in ("host", "port"):
            continue
        if not value:
            continue
        for suffix in VULNERABLE_SUFFIXES:
            if key.endswith(suffix):
                statuses[key[: -len(suffix)]] = STATUS_VULNERABLE
        if key.endswith(TESTED_SUFFIX):
            cls = key[: -len(TESTED_SUFFIX)]
            # A vulnerable flag wins over a tested flag for the same
            # class; don't downgrade an already-vulnerable cell.
            if statuses.get(cls) != STATUS_VULNERABLE:
                statuses[cls] = STATUS_CLEAN
    return statuses


@dataclass
class CoverageCell:
    target: str
    port: int
    vuln_class: str
    status: str


@dataclass
class CoverageMatrix:
    """All cells for one engagement, derived once from FactStore records
    and refreshed by re-calling `from_records` -- the matrix never
    mutates incrementally, so it can never drift from the facts it
    projects."""

    rows: List[Tuple[str, int]] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    cells: Dict[Tuple[str, int, str], str] = field(default_factory=dict)
    param_discovered: Dict[Tuple[str, int], bool] = field(default_factory=dict)
    injection_tested: Dict[Tuple[str, int], bool] = field(default_factory=dict)

    @classmethod
    def from_records(
        cls, records: List[Tuple[Tuple[str, int], Dict[str, Any]]]
    ) -> "CoverageMatrix":
        matrix = cls()
        seen_classes: List[str] = []

        for (host, port), record in records:
            target = f"{host}:{port}"
            matrix.rows.append((host, port))
            discovered = bool(
                record.get("arjun_params_discovered") or record.get("params_discovered")
            )
            matrix.param_discovered[(host, port)] = discovered
            matrix.injection_tested[(host, port)] = any(
                key.endswith(TESTED_SUFFIX) and record.get(key)
                for key in record
            )

            record_statuses = _classes_in_record(record)
            for cls, status in record_statuses.items():
                if cls not in matrix.classes:
                    matrix.classes.append(cls)
                    seen_classes.append(cls)
                matrix.cells[(host, port, cls)] = status

        # Stable class ordering: known classes first (in KNOWN_CLASSES
        # order), unknown classes after in first-seen order.
        known_order = [cls for cls, _ in KNOWN_CLASSES if cls in matrix.classes]
        unknown = [c for c in matrix.classes if c not in known_order]
        matrix.classes = known_order + unknown
        return matrix

    def status(self, host: str, port: int, vuln_class: str) -> str:
        return self.cells.get((host, port, vuln_class), STATUS_UNTESTED)

    def effective_status(self, host: str, port: int, vuln_class: str) -> str:
        """The status the model should act on, per class. An untested
        class on a target whose parameters WERE discovered surfaces as
        PARTIAL rather than UNTESTED -- "you found the attack surface and
        didn't follow through for this class" is a different instruction
        than "nobody looked here yet". Other classes on the same record
        being tested doesn't suppress this: each class's gap stands on
        its own."""
        base = self.status(host, port, vuln_class)
        if base == STATUS_UNTESTED and self.param_discovered.get((host, port)):
            return STATUS_PARTIAL
        return base

    def summary(self) -> Dict[str, int]:
        counts = {STATUS_VULNERABLE: 0, STATUS_CLEAN: 0, STATUS_PARTIAL: 0, STATUS_UNTESTED: 0}
        for (host, port), _ in [(r, None) for r in self.rows]:
            for cls in self.classes:
                counts[self.status(host, port, cls)] += 1
        return counts

    def open_threads(self) -> List[CoverageCell]:
        """Cells the harness would point the model at: partial cells
        (discovered-but-untested) and, secondarily, plain untested cells
        on targets that have some other coverage -- a target nobody ever
        touched at all is a different (and lower-priority) signal."""
        out: List[CoverageCell] = []
        for host, port in self.rows:
            for cls in self.classes:
                if self.effective_status(host, port, cls) == STATUS_PARTIAL:
                    out.append(CoverageCell(f"{host}:{port}", port, cls, STATUS_PARTIAL))
        return out

    def render_compact(self) -> str:
        """Token-cheap table for the per-turn state message. Column
        pruning: classes where every cell is untested carry no signal
        and are dropped entirely rather than printed as a wall of '-',
        UNLESS every class would be dropped (then print all -- an
        all-untested matrix is exactly what a fresh engagement looks
        like, and showing the full class list once tells the model what
        the harness tracks)."""
        if not self.rows:
            return "(no coverage data yet -- no tool has reported facts)"

        active_classes = [
            cls for cls in self.classes
            if any(self.status(h, p, cls) != STATUS_UNTESTED for h, p in self.rows)
        ] or list(self.classes)

        header = "target".ljust(22) + " ".join(
            _STATUS_SHORT.get(STATUS_UNTESTED) and cls[:9].ljust(9) for cls in active_classes
        )
        lines = [header.rstrip()]
        for host, port in self.rows:
            row = f"{host}:{port}".ljust(22)
            for cls in active_classes:
                status = self.effective_status(host, port, cls)
                row += _STATUS_SHORT[status].ljust(9)
            lines.append(row.rstrip())
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Studio UI shape: rows x classes grid plus per-cell detail."""
        grid = []
        for host, port in self.rows:
            row = {
                "target": f"{host}:{port}",
                "cells": {},
            }
            for cls in self.classes:
                row["cells"][cls] = self.effective_status(host, port, cls)
            grid.append(row)
        return {
            "classes": self.classes,
            "rows": grid,
            "summary": self.summary(),
        }
