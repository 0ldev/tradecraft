"""
Fact store: a deduplicated, deterministic record of what tools have
reported about each (host, port). No promotion/confidence math, no
severity judgment. A fact is written mechanically, straight from a
tool's parsed result, right after the execution loop dispatches that
tool -- never by the model directly, so a fact's correctness depends
only on the tool that produced it, same as why `log_finding` requires
real tool evidence rather than letting the model assert one.

This exists to solve one narrow problem: without it, the same (host,
port) fact can end up duplicated across several tool-result messages in
the conversation, and the model has no single place to check "what do we
already know about this port" without re-reading the whole transcript --
risking the model re-scanning a port it already scanned.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


class FactStore:
    """Keyed by (host, port). Each record accumulates fields over the
    engagement; a field reported again later overwrites the earlier
    value (last write wins) rather than duplicating the record.

    The "evidence" field is an exception to last-write-wins: it carries a
    pointer (an EvidenceStore key, "tool_id:target"), not an observation,
    and more than one tool can legitimately offload evidence for the same
    (host, port). Overwriting it like any other field would silently
    detach the record from an earlier tool's evidence the moment a
    later, unrelated tool touches the same port -- e.g. a record whose
    http_title/web_servers came from httpx_probe but whose single
    "evidence" pointer got overwritten by a later trufflehog call would
    dereference to an empty secret scan instead of the HTTP data the
    rest of the record is actually about. Evidence pointers accumulate
    instead, as a sorted, de-duplicated comma-separated list.
    """

    def __init__(self) -> None:
        self._ports: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def merge_port(self, host: str, port: int, fields: Dict[str, Any]) -> None:
        key = (host, port)
        record = self._ports.setdefault(key, {"host": host, "port": port})
        for field_name, value in fields.items():
            if value is None or value == "":
                continue
            if field_name == "evidence":
                existing = {e for e in record.get("evidence", "").split(",") if e}
                existing.add(str(value))
                record["evidence"] = ",".join(sorted(existing))
            else:
                record[field_name] = value

    def merge_many(self, facts: List[Dict[str, Any]]) -> None:
        for fact in facts:
            host = fact.get("host")
            port = fact.get("port")
            if host is None or port is None:
                continue
            fields = {k: v for k, v in fact.items() if k not in ("host", "port")}
            self.merge_port(host, port, fields)

    def sorted_records(self) -> List[Tuple[Tuple[str, int], Dict[str, Any]]]:
        """(host, port) -> record pairs, for budget-aware rendering
        (`tradecraft/execution/budget.py`). render() below stays the plain,
        unbounded view used wherever no budget applies (e.g. tests)."""
        return sorted(self._ports.items())

    def render(self) -> str:
        if not self._ports:
            return "(no facts recorded yet)"
        lines = []
        for (host, port), record in sorted(self._ports.items()):
            details = ", ".join(f"{k}={v}" for k, v in record.items() if k not in ("host", "port"))
            lines.append(f"{host}:{port} -- {details}" if details else f"{host}:{port}")
        return "\n".join(lines)
