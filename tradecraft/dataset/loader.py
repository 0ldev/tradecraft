"""
Decoupled engagement run loader for offline dataset extraction and evaluation.

Reads solely from persisted run directories on disk ($TRADECRAFT_HOME/targets/<target>/runs/<run_id>)
with zero dependency on the live execution loop or reporting modules.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from tradecraft.execution.run_dir import (
    get_tradecraft_home,
    get_target_dir,
    load_facts_json,
    read_manifest,
    resolve_run_dir,
)

_FINDING_LINE_RE = re.compile(
    r"^FINDING(?:\s+#(?P<id>\d+))?(?P<retracted>\s+\[RETRACTED\])?"
    r"(?:\s+\[(?:evidence:\s*(?P<ev>[^\]]+)|unverified:\s*(?P<unv>[^\]]+))\])?"
    r":\s*(?P<text>.*)$"
)
_RETRACTION_NOTE_RE = re.compile(
    r"^Finding\s+#(?P<id>\d+)\s+retracted:\s*(?P<reason>.*)$",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class RunDatasetSource:
    run_id: str
    run_dir: Path
    target: str
    manifest: Dict[str, Any] = field(default_factory=dict)
    trace_records: List[Dict[str, Any]] = field(default_factory=list)
    facts_records: List[Dict[str, Any]] = field(default_factory=list)
    active_finding_texts: List[str] = field(default_factory=list)
    retracted_finding_ids: Set[int] = field(default_factory=set)
    retracted_finding_texts: Set[str] = field(default_factory=set)
    retraction_reasons: Dict[int, str] = field(default_factory=dict)
    unverified_finding_ids: Set[int] = field(default_factory=set)
    logged_finding_evidence_ids: Dict[int, str] = field(default_factory=dict)
    tool_results_by_call_id: Dict[str, Any] = field(default_factory=dict)
    available_tools: Set[str] = field(default_factory=set)
    valid_evidence_ids: Set[str] = field(default_factory=set)
    discovered_hosts: Set[str] = field(default_factory=set)
    discovered_ips: Set[str] = field(default_factory=set)
    known_cves: Set[str] = field(default_factory=set)


def resolve_dataset_run_dirs(
    run_dir: Optional[str | Path] = None,
    target: Optional[str] = None,
    run: Optional[str] = None,
    all_runs: bool = False,
    tradecraft_home: Optional[Path] = None,
) -> List[Path]:
    """Resolves one or more run directories on disk for dataset extraction.

    Modes:
    - `run_dir`: explicit path to one run directory.
    - `target` + `all_runs=True`: all run directories under `$TRADECRAFT_HOME/targets/<target>/runs/`.
    - `target` + `run` (or default 'latest'): single run directory for `target`.
    - `all_runs=True` (with no `target`): all run directories across all targets in `$TRADECRAFT_HOME/targets/`.
    """
    if run_dir is not None and (target is not None or all_runs):
        raise ValueError("--run-dir cannot be combined with --target or --all")

    home = tradecraft_home or get_tradecraft_home()

    if run_dir is not None:
        p = Path(run_dir).expanduser().resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"run directory does not exist: {p}")
        if not (p / "trace.jsonl").is_file():
            raise FileNotFoundError(f"directory {p} has no trace.jsonl -- not a valid traced run directory")
        return [p]

    if target is not None:
        target_dir = get_target_dir(target, home)
        runs_parent = target_dir / "runs"
        if all_runs:
            if not runs_parent.is_dir():
                raise FileNotFoundError(f"no runs found for target '{target}'")
            dirs = sorted(
                d.resolve()
                for d in runs_parent.iterdir()
                if d.is_dir() and (d / "trace.jsonl").is_file()
            )
            if not dirs:
                raise FileNotFoundError(f"no traced runs found for target '{target}'")
            return dirs

        run_ref = run or "latest"
        try:
            _, resolved = resolve_run_dir(target, run_ref, home)
        except FileNotFoundError:
            if run_ref == "latest" and runs_parent.is_dir():
                candidates = sorted(
                    d.resolve()
                    for d in runs_parent.iterdir()
                    if d.is_dir() and (d / "trace.jsonl").is_file()
                )
                if candidates:
                    resolved = candidates[-1]
                else:
                    raise
            else:
                raise
        if not (resolved / "trace.jsonl").is_file():
            raise FileNotFoundError(f"run directory {resolved} has no trace.jsonl")
        return [resolved.resolve()]

    if all_runs:
        targets_base = home / "targets"
        if not targets_base.is_dir():
            raise FileNotFoundError(f"no targets directory found under {home}")
        dirs: List[Path] = []
        for t_dir in sorted(targets_base.iterdir()):
            runs_parent = t_dir / "runs"
            if not runs_parent.is_dir():
                continue
            for r_dir in sorted(runs_parent.iterdir()):
                if r_dir.is_dir() and (r_dir / "trace.jsonl").is_file():
                    dirs.append(r_dir.resolve())
        if not dirs:
            raise FileNotFoundError(f"no traced runs found under {targets_base}")
        return dirs

    raise ValueError("must provide one of --run-dir, --target, or --all")


def _extract_valid_ipv4s(text: str) -> Set[str]:
    ips: Set[str] = set()
    for match in _IPV4_RE.findall(text):
        try:
            ip = ipaddress.IPv4Address(match)
            if not ip.is_loopback and not ip.is_unspecified:
                ips.add(str(ip))
        except ipaddress.AddressValueError:
            continue
    return ips


def _extract_cves(text: str) -> Set[str]:
    return {m.upper() for m in _CVE_RE.findall(text)}


def load_run_dataset_source(run_dir: Path) -> RunDatasetSource:
    """Loads trace records, log signals, facts, evidence pointers, and discovered hosts/IPs from a run directory."""
    run_dir = run_dir.resolve()
    trace_path = run_dir / "trace.jsonl"
    if not trace_path.is_file():
        raise FileNotFoundError(f"trace.jsonl not found in {run_dir}")

    manifest: Dict[str, Any] = {}
    try:
        manifest = read_manifest(run_dir)
    except (FileNotFoundError, ValueError, OSError):
        manifest = {}

    run_id = str(manifest.get("run_id") or run_dir.name)
    target = str(manifest.get("target") or "")

    trace_records: List[Dict[str, Any]] = []
    tool_results_by_call_id: Dict[str, Any] = {}
    available_tools: Set[str] = set(manifest.get("tool_ids") or [])
    valid_evidence_ids: Set[str] = set()
    known_cves: Set[str] = set()

    with open(trace_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            trace_records.append(rec)

            req = rec.get("request") or {}
            for t_schema in req.get("tools") or []:
                if isinstance(t_schema, dict):
                    fn = t_schema.get("function") or {}
                    t_name = str(fn.get("name") or "").strip()
                    if t_name:
                        available_tools.add(t_name)

            msgs = req.get("messages") or []
            for msg in msgs:
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") == "user" and not target:
                    content = str(msg.get("content") or "")
                    if content.startswith("Begin the engagement against:"):
                        target = content.split("Begin the engagement against:", 1)[1].strip()
                elif msg.get("role") == "tool":
                    cid = str(msg.get("tool_call_id") or "")
                    raw_content = str(msg.get("content") or "")
                    known_cves.update(_extract_cves(raw_content))
                    if cid and cid not in tool_results_by_call_id:
                        try:
                            parsed_res = json.loads(raw_content)
                        except Exception:
                            parsed_res = raw_content
                        tool_results_by_call_id[cid] = parsed_res
                        if isinstance(parsed_res, dict) and parsed_res.get("evidence_id"):
                            valid_evidence_ids.add(str(parsed_res["evidence_id"]).strip())

    if not target and run_dir.parent.name == "runs":
        target = run_dir.parent.parent.name

    active_finding_texts: List[str] = []
    retracted_ids: Set[int] = set()
    retracted_texts: Set[str] = set()
    retraction_reasons: Dict[int, str] = {}
    unverified_ids: Set[int] = set()
    logged_finding_evidence_ids: Dict[int, str] = {}
    discovered_hosts: Set[str] = set()
    discovered_ips: Set[str] = set()

    if target:
        discovered_ips.update(_extract_valid_ipv4s(target))

    # First pass over log.txt to collect all retraction notes and finding lines
    parsed_findings_raw: List[tuple] = []
    log_path = run_dir / "log.txt"
    if log_path.is_file():
        try:
            log_text = log_path.read_text(encoding="utf-8")
        except OSError:
            log_text = ""
        discovered_ips.update(_extract_valid_ipv4s(log_text))
        known_cves.update(_extract_cves(log_text))
        for raw_line in log_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m = _FINDING_LINE_RE.match(line)
            if m:
                fid = int(m.group("id")) if m.group("id") else None
                is_retracted = bool(m.group("retracted"))
                ev_id = (m.group("ev") or "").strip()
                is_unverified = bool(m.group("unv")) or not bool(ev_id)
                ftext = (m.group("text") or "").strip()
                if fid is not None and ev_id:
                    logged_finding_evidence_ids[fid] = ev_id
                if is_retracted:
                    if fid is not None:
                        retracted_ids.add(fid)
                    if ftext:
                        retracted_texts.add(ftext)
                if is_unverified and fid is not None:
                    unverified_ids.add(fid)
                parsed_findings_raw.append((fid, is_retracted, ftext))
                continue
            if line.startswith("note:"):
                note_body = line[len("note:"):].strip()
                rm = _RETRACTION_NOTE_RE.match(note_body)
                if rm:
                    fid = int(rm.group("id"))
                    retracted_ids.add(fid)
                    retraction_reasons[fid] = rm.group("reason").strip()

    for fid, is_retracted, ftext in parsed_findings_raw:
        if is_retracted or (fid is not None and fid in retracted_ids):
            if ftext:
                retracted_texts.add(ftext)
        elif ftext:
            active_finding_texts.append(ftext)

    facts_store = load_facts_json(run_dir)
    facts_records: List[Dict[str, Any]] = []
    for (host, _), record in facts_store.sorted_records():
        facts_records.append(dict(record))
        if host:
            if _extract_valid_ipv4s(host) and host in _extract_valid_ipv4s(host):
                discovered_ips.add(host)
            else:
                discovered_hosts.add(host)
        for key, val in record.items():
            if key in ("evidence", "evidence_id"):
                if isinstance(val, str) and val.strip():
                    valid_evidence_ids.add(val.strip())
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and item.strip():
                            valid_evidence_ids.add(item.strip())
            if isinstance(val, str):
                discovered_ips.update(_extract_valid_ipv4s(val))
                known_cves.update(_extract_cves(val))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        discovered_ips.update(_extract_valid_ipv4s(item))
                        known_cves.update(_extract_cves(item))

    # Also index any persisted evidence/<sub_target>/<tool>.json files
    evidence_dir = run_dir / "evidence"
    if evidence_dir.is_dir():
        for sub_dir in evidence_dir.iterdir():
            if not sub_dir.is_dir():
                continue
            for ev_file in sub_dir.glob("*.json"):
                tool_name = ev_file.stem
                valid_evidence_ids.add(f"{tool_name}:{sub_dir.name}")
                try:
                    ev_text = ev_file.read_text(encoding="utf-8")
                    known_cves.update(_extract_cves(ev_text))
                except OSError:
                    pass

    return RunDatasetSource(
        run_id=run_id,
        run_dir=run_dir,
        target=target,
        manifest=manifest,
        trace_records=trace_records,
        facts_records=facts_records,
        active_finding_texts=active_finding_texts,
        retracted_finding_ids=retracted_ids,
        retracted_finding_texts=retracted_texts,
        retraction_reasons=retraction_reasons,
        unverified_finding_ids=unverified_ids,
        logged_finding_evidence_ids=logged_finding_evidence_ids,
        tool_results_by_call_id=tool_results_by_call_id,
        available_tools=available_tools,
        valid_evidence_ids=valid_evidence_ids,
        discovered_hosts=discovered_hosts,
        discovered_ips=discovered_ips,
        known_cves=known_cves,
    )
