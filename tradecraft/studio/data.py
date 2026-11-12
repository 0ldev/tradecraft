"""Craft Studio data layer (Tradecraft 2.0, Phase 3).

Pure functions that read a run directory (the same artifacts
execution/loop.py persists: manifest.json, log.txt, facts.json,
trace.jsonl) into JSON shapes the dashboard consumes. No server, no
framework -- trivially testable, and the API layer in app.py stays
thin. A run's data is read-only here: the Studio observes engagements,
it never mutates them.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from tradecraft.coverage.matrix import CoverageMatrix

RUN_DIR_FIELDS = ("manifest.json", "log.txt", "facts.json", "trace.jsonl", "graph.json")


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def parse_log(log_path: Path) -> Dict[str, Any]:
    """Split the persisted log into notes/findings with their tags --
    the same render the engagement log used, re-parsed for display.
    The log is plain text by design; this parser is correspondingly
    tolerant (an unparseable line still shows up, as raw text)."""
    notes: List[str] = []
    findings: List[Dict[str, Any]] = []
    if not log_path.is_file():
        return {"notes": notes, "findings": findings}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("FINDING #"):
            body = line
            finding_id = None
            rest = line[len("FINDING #"):]
            id_part = rest.split(" ", 1)[0]
            if id_part.isdigit():
                finding_id = int(id_part)
                body = f"FINDING #{id_part}" + rest[len(id_part):]
            findings.append({"raw": body, "finding_id": finding_id})
        elif line.startswith("note:"):
            notes.append(line[len("note:"):].strip())
        else:
            # Retraction records and future entry kinds -- keep visible.
            notes.append(line)
    return {"notes": notes, "findings": findings}


def tail_lines(path: Path, limit: int = 200) -> List[str]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-limit:]


def run_data(run_dir: str | Path) -> Dict[str, Any]:
    """Everything the dashboard needs for one run, in one payload."""
    run_path = Path(run_dir)
    manifest = load_json(run_path / "manifest.json") or {}
    facts_payload = load_json(run_path / "facts.json")

    matrix = None
    records = []
    if facts_payload:
        for entry in facts_payload.get("records", []):
            if isinstance(entry, dict) and "host" in entry and "port" in entry:
                host, port = entry.pop("host"), entry.pop("port")
                records.append(((host, port), entry))
        matrix = CoverageMatrix.from_records(records)

    log = parse_log(run_path / "log.txt")
    trace_tail = tail_lines(run_path / "trace.jsonl")

    return {
        "run_id": run_path.name,
        "path": str(run_path),
        "manifest": manifest,
        "exists": run_path.is_dir(),
        "coverage": matrix.to_dict() if matrix else None,
        "log": log,
        "trace_lines": trace_tail,
        "graph": load_json(run_path / "graph.json"),
    }


def list_runs(home: str | Path | None = None) -> List[Dict[str, str]]:
    """Scan the TRADECRAFT_HOME hierarchy
    (<home>/targets/<target>/runs/<run_id>) newest-first."""
    base = Path(home) if home else Path.home() / ".tradecraft"
    runs_root = base / "targets"
    out: List[Dict[str, str]] = []
    if not runs_root.is_dir():
        return out
    for manifest_path in sorted(runs_root.glob("*/runs/*/manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        run_path = manifest_path.parent
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            manifest = {}
        out.append({
            "run_id": run_path.name,
            "target": manifest.get("target") or run_path.parent.parent.name,
            "path": str(run_path),
            "turns_used": str(manifest.get("turns_used", "")),
            "findings_count": str(manifest.get("findings_count", "")),
        })
    return out
