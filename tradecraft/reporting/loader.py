"""
Decoupled engagement run loader and canonical report data model.

Allows generating comprehensive security assessment reports from either:
- Any persisted run directory on disk ($TRADECRAFT_HOME/targets/<target>/runs/<run_id>),
  including runs that were interrupted before finalization.
- An in-memory EngagementResult returned directly by run_engagement().
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.execution.loop import EngagementResult
from tradecraft.execution.run_dir import (
    get_tradecraft_home,
    get_target_dir,
    load_facts_json,
    read_manifest,
    resolve_run_dir,
)
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore

_FINDING_LINE_RE = re.compile(
    r"^FINDING(?:\s+#(?P<id>\d+))?(?P<retracted>\s+\[RETRACTED\])?"
    r"(?:\s+\[(?:evidence:\s*(?P<ev>[^\]]+)|unverified:\s*(?P<unv>[^\]]+))\])?"
    r":\s*(?P<text>.*)$"
)
_TRAILING_TAG_RE = re.compile(
    r"^(?P<text>.*?)\s+\[(?:evidence:\s*(?P<ev>[^\]]+)|unverified:\s*(?P<unv>[^\]]+))\]\s*$"
)
_RETRACTION_NOTE_RE = re.compile(
    r"^Finding\s+#(?P<id>\d+)\s+retracted:\s*(?P<reason>.*)$",
    re.IGNORECASE,
)
_FACT_SPLIT_RE = re.compile(r",\s*(?=[a-zA-Z_][a-zA-Z0-9_]*=)")

MAX_EVIDENCE_SNIPPET_CHARS = 2400


@dataclass
class ParsedFinding:
    finding_id: Optional[int]
    text: str
    raw_line: str
    evidence_id: Optional[str] = None
    verified: bool = False
    retracted: bool = False
    retraction_reason: Optional[str] = None
    title: str = ""
    tool_id: Optional[str] = None
    asset: Optional[str] = None
    evidence_data: Any = None
    evidence_snippet: Optional[str] = None
    evidence_image_b64: Optional[str] = None
    evidence_image_mime: Optional[str] = None

    def source_tag(self) -> str:
        if self.evidence_id:
            return f"[evidence: {self.evidence_id}]"
        return "[unverified: no evidence_id]"

    def formatted_bullet(self) -> str:
        return f"{self.text} {self.source_tag()}"


@dataclass
class TurnToolCall:
    call_id: str
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    result: Any = None
    evidence_id: Optional[str] = None


@dataclass
class TurnHistoryEntry:
    turn: int
    timestamp: Optional[str] = None
    call_kind: str = "turn"
    duration_seconds: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    truncation_retries: int = 0
    network_retries: int = 0
    finish_reason: Optional[str] = None
    reasoning: Optional[str] = None
    assistant_text: Optional[str] = None
    tool_calls: List[TurnToolCall] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class RunReportBundle:
    target: str
    run_id: Optional[str] = None
    run_dir: Optional[Path] = None
    manifest: Dict[str, Any] = field(default_factory=dict)
    turns_used: int = 0
    stats: Dict[str, Any] = field(default_factory=dict)
    active_findings: List[ParsedFinding] = field(default_factory=list)
    retracted_findings: List[ParsedFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    log_lines: List[str] = field(default_factory=list)
    facts: FactStore = field(default_factory=FactStore)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    evidence_keys: List[str] = field(default_factory=list)
    closing_notes: str = ""
    history: List[TurnHistoryEntry] = field(default_factory=list)
    executive_summary: str = ""
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    @property
    def is_empty(self) -> bool:
        return not self.active_findings and self.facts.render() == "(no facts recorded yet)"


def _derive_finding_title(text: str, max_len: int = 88) -> str:
    """Extracts a concise, scannable title from the finding statement."""
    clean = text.strip()
    if not clean:
        return "Security Finding"
    for sep in (" — ", " -- ", ": ", ". "):
        if sep in clean:
            head = clean.split(sep, 1)[0].strip()
            if 12 <= len(head) <= max_len:
                return head
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 1].rsplit(" ", 1)[0] + "…"


def _split_evidence_id(evidence_id: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not evidence_id or ":" not in evidence_id:
        return None, None
    tool_id, asset = evidence_id.split(":", 1)
    return tool_id.strip() or None, asset.strip() or None


def _hydrate_finding_evidence(finding: ParsedFinding, evidence_store: Optional[EvidenceStore]) -> None:
    """Resolves the finding's evidence_id against EvidenceStore to attach a
    formatted proof snippet or binary screenshot."""
    if not evidence_store or not finding.tool_id or not finding.asset:
        return

    read_res = evidence_store.read(target=finding.asset, tool_id=finding.tool_id)
    if not isinstance(read_res, dict) or "error" in read_res:
        return

    if read_res.get("is_binary") and read_res.get("file_path"):
        bin_path = Path(read_res["file_path"])
        if bin_path.is_file() and bin_path.stat().st_size <= 5 * 1024 * 1024:
            ext = bin_path.suffix.lower().lstrip(".")
            if ext in ("png", "jpg", "jpeg", "gif", "webp"):
                mime = "image/jpeg" if ext in ("jpg", "jpeg") else f"image/{ext}"
                try:
                    raw_bytes = bin_path.read_bytes()
                    finding.evidence_image_b64 = base64.b64encode(raw_bytes).decode("ascii")
                    finding.evidence_image_mime = mime
                except OSError:
                    pass
        finding.evidence_data = {
            k: v for k, v in read_res.items() if k != "file_path"
        }
        finding.evidence_snippet = read_res.get("note") or f"Binary evidence ({read_res.get('size_bytes', 0)} bytes)"
        return

    payload = read_res.get("evidence", read_res)
    finding.evidence_data = payload
    try:
        serialized = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    except Exception:
        serialized = str(payload)

    if len(serialized) > MAX_EVIDENCE_SNIPPET_CHARS:
        serialized = (
            serialized[:MAX_EVIDENCE_SNIPPET_CHARS]
            + f"\n... [truncated {len(serialized) - MAX_EVIDENCE_SNIPPET_CHARS} chars; full record in evidence/{finding.asset}/{finding.tool_id}.json]"
        )
    finding.evidence_snippet = serialized


def parse_finding_string(raw: str, index: int = 1, evidence_store: Optional[EvidenceStore] = None) -> ParsedFinding:
    """Parses either a log.txt FINDING line or an EngagementMemory.findings() string."""
    line = raw.strip()
    m = _FINDING_LINE_RE.match(line)
    if m:
        fid_str = m.group("id")
        fid = int(fid_str) if fid_str is not None else index
        retracted = bool(m.group("retracted"))
        ev_id = (m.group("ev") or "").strip() or None
        text = m.group("text").strip()
    else:
        fid = index
        retracted = False
        ev_id = None
        text = line
        if text.startswith("FINDING:"):
            text = text[len("FINDING:") :].strip()

    # Also check if source_tag is at the tail (as produced by EngagementMemory.findings())
    tail_m = _TRAILING_TAG_RE.match(text)
    if tail_m:
        text = tail_m.group("text").strip()
        if not ev_id and tail_m.group("ev"):
            ev_id = tail_m.group("ev").strip() or None

    tool_id, asset = _split_evidence_id(ev_id)
    pf = ParsedFinding(
        finding_id=fid,
        text=text,
        raw_line=line,
        evidence_id=ev_id,
        verified=bool(ev_id),
        retracted=retracted,
        title=_derive_finding_title(text),
        tool_id=tool_id,
        asset=asset,
    )
    _hydrate_finding_evidence(pf, evidence_store)
    return pf


def parse_log_text(
    log_text: str,
    evidence_store: Optional[EvidenceStore] = None,
) -> Tuple[List[ParsedFinding], List[ParsedFinding], List[str], List[str]]:
    """Parses log.txt contents into (active_findings, retracted_findings, notes, raw_lines).

    Handles append-only retractions where `FINDING #N ...` was written earlier in
    log.txt and `note: Finding #N retracted: <reason>` was appended on a later turn.
    """
    all_findings: List[ParsedFinding] = []
    findings_by_id: Dict[int, ParsedFinding] = {}
    notes: List[str] = []
    raw_lines: List[str] = []
    next_seq = 1

    for raw_line in log_text.splitlines():
        clean = raw_line.strip()
        if not clean:
            continue
        raw_lines.append(clean)

        if clean.startswith("FINDING"):
            pf = parse_finding_string(clean, index=next_seq, evidence_store=evidence_store)
            if pf.finding_id is not None:
                next_seq = max(next_seq, pf.finding_id + 1)
                findings_by_id[pf.finding_id] = pf
            else:
                pf.finding_id = next_seq
                findings_by_id[next_seq] = pf
                next_seq += 1
            all_findings.append(pf)
        elif clean.startswith("note:"):
            note_body = clean[len("note:") :].strip()
            notes.append(note_body)
            ret_m = _RETRACTION_NOTE_RE.match(note_body)
            if ret_m:
                target_id = int(ret_m.group("id"))
                reason = ret_m.group("reason").strip()
                if target_id in findings_by_id:
                    findings_by_id[target_id].retracted = True
                    findings_by_id[target_id].retraction_reason = reason
        else:
            notes.append(clean)

    active = [f for f in all_findings if not f.retracted]
    retracted = [f for f in all_findings if f.retracted]
    return active, retracted, notes, raw_lines


def parse_facts_from_state_block(state_text: str) -> FactStore:
    """Parses the `## Known Facts` section from a rendered state message back into a FactStore."""
    store = FactStore()
    if "## Known Facts" not in state_text:
        return store

    after_header = state_text.split("## Known Facts", 1)[1]
    if "## Engagement Budget" in after_header:
        block = after_header.split("## Engagement Budget", 1)[0]
    else:
        block = after_header

    for line in block.splitlines():
        s = line.strip()
        if (
            not s
            or s.startswith("What tools have reported")
            or s == "(no facts recorded yet)"
            or s.startswith("[...")
        ):
            continue
        if " -- " in s:
            host_port, details_str = s.split(" -- ", 1)
        else:
            host_port, details_str = s, ""

        if ":" not in host_port:
            continue
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            continue

        fields: Dict[str, Any] = {}
        if details_str.strip():
            for pair in _FACT_SPLIT_RE.split(details_str.strip()):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    k = k.strip()
                    v_str = v.strip()
                    if v_str == "True":
                        fields[k] = True
                    elif v_str == "False":
                        fields[k] = False
                    elif v_str.isdigit():
                        fields[k] = int(v_str)
                    else:
                        fields[k] = v_str
        store.merge_port(host.strip(), port, fields)
    return store


def load_trace_data(trace_path: Path) -> Tuple[List[TurnHistoryEntry], Dict[str, Any], str, FactStore]:
    """Reads trace.jsonl to reconstruct:
    - TurnHistoryEntry list (with reasoning, tool calls, arguments, results, tokens, timing)
    - Call summary stats dict
    - Closing report text (if the run produced one)
    - Recovered FactStore (from the latest state message in trace.jsonl)
    """
    records: List[Dict[str, Any]] = []
    if trace_path.is_file():
        with open(trace_path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    records.append(json.loads(s))
                except Exception:
                    continue

    empty_stats = {
        "total_llm_calls": 0,
        "successful_calls": 0,
        "failed_calls": 0,
        "truncation_retries": 0,
        "network_retries": 0,
        "total_prompt_tokens": 0,
        "total_completion_tokens": 0,
        "total_tokens": 0,
        "total_wall_seconds": 0.0,
    }
    if not records:
        return [], empty_stats, "", FactStore()

    successes = [r for r in records if r.get("error") is None]
    failures = [r for r in records if r.get("error") is not None]

    def _sum_usage(key: str) -> int:
        return sum(((r.get("usage") or {}).get(key) or 0) for r in successes)

    stats = {
        "total_llm_calls": len(records),
        "successful_calls": len(successes),
        "failed_calls": len(failures),
        "truncation_retries": sum(1 for r in records if (r.get("truncation_attempt") or 0) > 0),
        "network_retries": sum(1 for r in records if (r.get("network_attempt") or 0) > 0),
        "total_prompt_tokens": _sum_usage("prompt_tokens"),
        "total_completion_tokens": _sum_usage("completion_tokens"),
        "total_tokens": _sum_usage("total_tokens"),
        "total_wall_seconds": round(sum(float(r.get("duration_seconds") or 0.0) for r in records), 2),
    }

    # Recover facts from the latest record that has a state message
    recovered_facts = FactStore()
    for rec in reversed(records):
        msgs = (rec.get("request") or {}).get("messages") or []
        if msgs and isinstance(msgs[-1], dict):
            last_content = str(msgs[-1].get("content") or "")
            if "## Known Facts" in last_content:
                recovered_facts = parse_facts_from_state_block(last_content)
                if recovered_facts.sorted_records():
                    break

    # Extract tool call details (arguments + results) from the conversation messages
    # across trace records. Because conversation trimming can drop older messages in
    # later turns, we scan all records in order and index by tool_call_id.
    tool_calls_by_id: Dict[str, TurnToolCall] = {}
    assistant_turn_tool_ids: List[List[str]] = []
    seen_assistant_Keys: set[str] = set()

    def _register_tool_calls(tc_list: List[Any], record_turn_order: bool = True) -> None:
        ids = [str(tc.get("id") or "") for tc in tc_list if isinstance(tc, dict)]
        sig = ",".join(ids)
        if record_turn_order and sig and sig not in seen_assistant_Keys:
            seen_assistant_Keys.add(sig)
            assistant_turn_tool_ids.append(ids)
        for tc in tc_list:
            if not isinstance(tc, dict):
                continue
            cid = str(tc.get("id") or "")
            fn = tc.get("function") or {}
            name = str(fn.get("name") or "")
            raw_args = fn.get("arguments") or "{}"
            if isinstance(raw_args, str):
                try:
                    parsed_args = json.loads(raw_args)
                except Exception:
                    parsed_args = {"_raw": raw_args}
            elif isinstance(raw_args, dict):
                parsed_args = raw_args
            else:
                parsed_args = {}
            if cid and cid not in tool_calls_by_id:
                tool_calls_by_id[cid] = TurnToolCall(
                    call_id=cid,
                    name=name,
                    arguments=parsed_args if isinstance(parsed_args, dict) else {},
                )

    for rec in records:
        if rec.get("tool_calls") and not rec.get("error"):
            _register_tool_calls(rec.get("tool_calls") or [], record_turn_order=False)
        msgs = (rec.get("request") or {}).get("messages") or []
        for msg in msgs:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role")
            if role == "assistant" and msg.get("tool_calls"):
                _register_tool_calls(msg.get("tool_calls") or [], record_turn_order=True)
            elif role == "tool":
                cid = str(msg.get("tool_call_id") or "")
                if cid and cid in tool_calls_by_id and tool_calls_by_id[cid].result is None:
                    raw_content = msg.get("content") or ""
                    try:
                        res_obj = json.loads(raw_content)
                    except Exception:
                        res_obj = raw_content
                    tool_calls_by_id[cid].result = res_obj
                    if isinstance(res_obj, dict) and res_obj.get("evidence_id"):
                        tool_calls_by_id[cid].evidence_id = str(res_obj["evidence_id"])

    # Group trace records by (turn, call_kind)
    turns_map: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
    for rec in records:
        t_num = int(rec.get("turn") or 0)
        c_kind = str(rec.get("call_kind") or "turn")
        turns_map.setdefault((t_num, c_kind), []).append(rec)

    history: List[TurnHistoryEntry] = []
    closing_notes = ""
    assistant_tc_idx = 0

    for (t_num, c_kind), call_group in sorted(turns_map.items(), key=lambda x: (x[0][0], 0 if x[0][1] == "turn" else 1)):
        last_call = call_group[-1]
        duration = round(sum(float(c.get("duration_seconds") or 0.0) for c in call_group), 2)
        p_tok = sum(((c.get("usage") or {}).get("prompt_tokens") or 0) for c in call_group if not c.get("error"))
        c_tok = sum(((c.get("usage") or {}).get("completion_tokens") or 0) for c in call_group if not c.get("error"))
        t_tok = sum(((c.get("usage") or {}).get("total_tokens") or 0) for c in call_group if not c.get("error"))
        trunc_r = sum(1 for c in call_group if (c.get("truncation_attempt") or 0) > 0)
        net_r = sum(1 for c in call_group if (c.get("network_attempt") or 0) > 0)

        tc_names = last_call.get("tool_call_names") or []
        direct_tcs = last_call.get("tool_calls") or []
        resolved_tcs: List[TurnToolCall] = []
        if direct_tcs:
            direct_ids = [str(tc.get("id") or "") for tc in direct_tcs if isinstance(tc, dict)]
            if assistant_tc_idx < len(assistant_turn_tool_ids) and assistant_turn_tool_ids[assistant_tc_idx] == direct_ids:
                assistant_tc_idx += 1
            resolved_tcs = [tool_calls_by_id[cid] for cid in direct_ids if cid in tool_calls_by_id]
        if not resolved_tcs and tc_names:
            if assistant_tc_idx < len(assistant_turn_tool_ids):
                ids_for_turn = assistant_turn_tool_ids[assistant_tc_idx]
                assistant_tc_idx += 1
                resolved_tcs = [tool_calls_by_id[cid] for cid in ids_for_turn if cid in tool_calls_by_id]
            if not resolved_tcs:
                resolved_tcs = [
                    TurnToolCall(call_id=f"turn_{t_num}_{i}", name=str(n))
                    for i, n in enumerate(tc_names, 1)
                ]

        content_str = (last_call.get("content") or "").strip()
        reasoning_str = (last_call.get("reasoning_content") or "").strip() or None
        finish_reason = last_call.get("finish_reason")

        if (c_kind == "final_report" or (not tc_names and finish_reason == "stop")) and content_str:
            closing_notes = content_str

        history.append(
            TurnHistoryEntry(
                turn=t_num,
                timestamp=last_call.get("timestamp"),
                call_kind=c_kind,
                duration_seconds=duration,
                prompt_tokens=p_tok,
                completion_tokens=c_tok,
                total_tokens=t_tok,
                truncation_retries=trunc_r,
                network_retries=net_r,
                finish_reason=finish_reason,
                reasoning=reasoning_str,
                assistant_text=content_str or None,
                tool_calls=resolved_tcs,
                error=last_call.get("error"),
            )
        )

    return history, stats, closing_notes, recovered_facts


def resolve_report_run_dir(
    *,
    run_dir: str | Path | None = None,
    target: str | None = None,
    run: str | None = None,
    tradecraft_home: Path | None = None,
) -> Path:
    """Resolves a run directory from either --run-dir or --target [--run ...].
    If --run is 'latest' (or omitted) and no 'latest' symlink exists yet (e.g., an
    interrupted run), falls back to the newest chronological run directory under
    the target that contains data (non-empty log.txt, facts.json, or trace.jsonl)."""
    if run_dir and target:
        raise ValueError("specify either --run-dir or --target, not both")
    if not run_dir and not target:
        raise ValueError("specify either --run-dir or --target")

    if run_dir:
        p = Path(run_dir).expanduser().resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"run directory '{run_dir}' does not exist")
        resolved = p
    else:
        run_ref = run or "latest"
        home = tradecraft_home or get_tradecraft_home()
        try:
            _, resolved = resolve_run_dir(target, run_ref, tradecraft_home=home)  # type: ignore[arg-type]
            resolved = resolved.resolve()
        except FileNotFoundError:
            if run_ref != "latest":
                raise
            # Fallback for interrupted runs where 'latest' symlink wasn't created yet
            t_dir = get_target_dir(target, home)  # type: ignore[arg-type]
            runs_dir = t_dir / "runs"
            if not runs_dir.is_dir():
                raise FileNotFoundError(f"no runs found for target '{target}'")
            candidates = sorted(
                [d for d in runs_dir.iterdir() if d.is_dir()],
                key=lambda d: d.name,
                reverse=True,
            )
            if not candidates:
                raise FileNotFoundError(f"no runs found for target '{target}'")
            # Prefer the most recent run that actually recorded log/trace/facts data
            non_empty = [
                d for d in candidates
                if (
                    ((d / "log.txt").is_file() and (d / "log.txt").stat().st_size > 0)
                    or ((d / "facts.json").is_file() and (d / "facts.json").stat().st_size > 2)
                    or ((d / "trace.jsonl").is_file() and (d / "trace.jsonl").stat().st_size > 0)
                )
            ]
            resolved = (non_empty[0] if non_empty else candidates[0]).resolve()

    has_artifacts = any(
        (resolved / name).exists()
        for name in ("log.txt", "manifest.json", "facts.json", "trace.jsonl")
    )
    if not has_artifacts:
        raise FileNotFoundError(f"error: {resolved} contains no engagement artifacts -- not a valid run directory")

    return resolved


def load_run_bundle(run_dir: str | Path) -> RunReportBundle:
    """Reconstructs a complete RunReportBundle from a persisted run directory on disk."""
    rdir = Path(run_dir).expanduser().resolve()
    if not rdir.is_dir():
        raise FileNotFoundError(f"run directory '{run_dir}' does not exist")

    try:
        manifest = read_manifest(rdir)
    except FileNotFoundError:
        manifest = {}

    evidence_dir = rdir / "evidence"
    evidence_store = EvidenceStore(persist_dir=evidence_dir) if evidence_dir.is_dir() else EvidenceStore()

    log_path = rdir / "log.txt"
    log_text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
    active_findings, retracted_findings, notes, log_lines = parse_log_text(log_text, evidence_store=evidence_store)

    trace_path = rdir / "trace.jsonl"
    history, trace_stats, trace_closing, recovered_facts = load_trace_data(trace_path)

    facts_store = load_facts_json(rdir)
    if not facts_store.sorted_records() and recovered_facts.sorted_records():
        facts_store = recovered_facts

    target = manifest.get("target")
    if not target:
        recs = facts_store.sorted_records()
        if recs:
            target = recs[0][0][0]
        elif rdir.parent.name == "runs":
            target = rdir.parent.parent.name
        else:
            target = rdir.name

    run_id = manifest.get("run_id") or rdir.name
    turns_used = int(manifest.get("turns_used") or 0)
    if turns_used == 0 and history:
        turns_used = max((h.turn for h in history), default=0)

    closing_notes = trace_closing
    if not closing_notes and manifest.get("ended_at") is None and history:
        closing_notes = (
            f"(engagement run {run_id} ended or was inspected at turn {turns_used} "
            "before a final closing message was emitted)"
        )

    return RunReportBundle(
        target=str(target),
        run_id=str(run_id),
        run_dir=rdir,
        manifest=manifest,
        turns_used=turns_used,
        stats=trace_stats,
        active_findings=active_findings,
        retracted_findings=retracted_findings,
        notes=notes,
        log_lines=log_lines,
        facts=facts_store,
        evidence=evidence_store,
        evidence_keys=evidence_store.keys() if evidence_dir.is_dir() else [],
        closing_notes=closing_notes,
        history=history,
    )


def bundle_from_result(
    result: EngagementResult,
    *,
    target: Optional[str] = None,
) -> RunReportBundle:
    """Builds a RunReportBundle from an in-memory EngagementResult (enhancing with
    on-disk manifest/trace/log artifacts if result.run_dir exists on disk)."""
    if result.run_dir and Path(result.run_dir).is_dir():
        try:
            disk_bundle = load_run_bundle(result.run_dir)
            if target:
                disk_bundle.target = target
            elif result.target:
                disk_bundle.target = result.target
            if result.report and result.report.strip():
                disk_bundle.closing_notes = result.report
            if result.turns_used:
                disk_bundle.turns_used = result.turns_used
            if result.stats:
                disk_bundle.stats = result.stats
            if result.facts and result.facts.sorted_records():
                disk_bundle.facts = result.facts
            if not disk_bundle.active_findings and result.findings:
                disk_bundle.active_findings = [
                    parse_finding_string(f, index=i, evidence_store=result.evidence)
                    for i, f in enumerate(result.findings, 1)
                ]
            return disk_bundle
        except Exception:
            pass

    target_name = target or getattr(result, "target", None)
    if not target_name:
        sorted_recs = result.facts.sorted_records()
        target_name = sorted_recs[0][0][0] if sorted_recs else "Target"

    active_findings = [
        parse_finding_string(f, index=i, evidence_store=result.evidence)
        for i, f in enumerate(result.findings or [], 1)
    ]

    # Build lightweight turn history from result.transcript if trace.jsonl wasn't available
    history: List[TurnHistoryEntry] = []
    if result.transcript:
        tool_results_by_id: Dict[str, Any] = {}
        for msg in result.transcript:
            if isinstance(msg, dict) and msg.get("role") == "tool":
                cid = str(msg.get("tool_call_id") or "")
                raw_c = msg.get("content") or ""
                try:
                    tool_results_by_id[cid] = json.loads(raw_c)
                except Exception:
                    tool_results_by_id[cid] = raw_c

        turn_idx = 0
        for msg in result.transcript:
            if not isinstance(msg, dict) or msg.get("role") != "assistant":
                continue
            turn_idx += 1
            tcs: List[TurnToolCall] = []
            for tc in msg.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                cid = str(tc.get("id") or "")
                fn = tc.get("function") or {}
                raw_args = fn.get("arguments") or "{}"
                try:
                    args_dict = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except Exception:
                    args_dict = {}
                res_val = tool_results_by_id.get(cid)
                ev_id = res_val.get("evidence_id") if isinstance(res_val, dict) else None
                tcs.append(
                    TurnToolCall(
                        call_id=cid,
                        name=str(fn.get("name") or ""),
                        arguments=args_dict,
                        result=res_val,
                        evidence_id=ev_id,
                    )
                )
            history.append(
                TurnHistoryEntry(
                    turn=turn_idx,
                    assistant_text=(msg.get("content") or "").strip() or None,
                    reasoning=(msg.get("reasoning_content") or "").strip() or None,
                    tool_calls=tcs,
                )
            )

    return RunReportBundle(
        target=target_name,
        run_id=result.run_id,
        run_dir=Path(result.run_dir) if result.run_dir else None,
        turns_used=result.turns_used,
        stats=result.stats or {},
        active_findings=active_findings,
        facts=result.facts,
        evidence=result.evidence,
        evidence_keys=result.evidence.keys() if result.evidence else [],
        closing_notes=result.report or "",
        history=history,
    )
