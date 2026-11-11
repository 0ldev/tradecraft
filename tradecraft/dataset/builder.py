"""
Transforms persisted Tradecraft engagement runs into SFT and DPO/preference datasets,
with turn-level scoring, behavioral tagging, redundancy/tunnel-vision detection,
and a tool-conditioned 8-dimension run evaluation framework.
"""
from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from tradecraft.dataset.loader import RunDatasetSource
from tradecraft.dataset.scrubber import apply_scrub_map, build_scrub_map, extract_seed_identifiers

# Markers from tradecraft/memory/cross_engagement.py and run_dir.py::load_seed_context.
_SEED_MARKERS = (
    "--- Cross-engagement memory for root domain",
    "--- Known from a prior engagement",
)


def _extract_system_prompt(trace_records: List[Dict[str, Any]]) -> str:
    for rec in trace_records:
        for msg in (rec.get("request") or {}).get("messages") or []:
            if isinstance(msg, dict) and msg.get("role") == "system":
                return str(msg.get("content") or "")
    return ""


def _was_seeded(system_prompt: str) -> bool:
    return any(marker in system_prompt for marker in _SEED_MARKERS)


def _build_scrub_patterns(source: "RunDatasetSource") -> List[Tuple[re.Pattern[str], str]]:
    system_prompt = _extract_system_prompt(source.trace_records)
    seed_hosts, seed_ips, seed_run_ids = extract_seed_identifiers(system_prompt)
    return build_scrub_map(
        source.target,
        set(source.discovered_hosts) | seed_hosts,
        set(source.discovered_ips) | seed_ips,
        seed_run_ids=seed_run_ids,
    )

SUPPORTED_DATASET_FORMATS = ("sft", "dpo", "checklist")

SUPPORTED_BEHAVIORS = (
    "recon_breadth",
    "parallel_batching",
    "evidence_hydration",
    "pivot_on_lead",
    "evidence_discipline",
    "clean_reporting",
)

_DISPATCH_ERROR_SUBSTRINGS = (
    "unknown tool",
    "is disabled for this engagement",
    "is destructive and --allow-destructive",
    "missing required parameter",
    "malformed tool arguments",
)

_RECON_BREADTH_TOOLS = frozenset({
    "subfinder",
    "amass",
    "dnsx",
    "crtsh_lookup",
    "subdomain_permute",
    "cloud_enum",
    "nmap_scan",
    "naabu_scan",
    "katana",
    "gau",
    "ffuf",
    "feroxbuster",
    "gobuster",
    "httpx_probe",
})

_INJECTION_TOOLS = frozenset({
    "sqlmap",
    "sqlmap_scan",
    "ghauri",
    "dalfox",
    "dalfox_xss",
    "commix",
    "commix_scan",
    "tplmap",
    "tplmap_scan",
    "nosql_injection_probe",
    "xxe_probe",
    "ssrf_probe",
    "open_redirect_probe",
    "crlf_injection_probe",
})

_PIVOT_PROBE_TOOLS = frozenset({
    "sqlmap_scan",
    "ghauri",
    "dalfox_xss",
    "arjun",
    "graphql_introspect",
    "commix_scan",
    "tplmap_scan",
    "ssrf_probe",
    "xxe_probe",
    "nosql_injection_probe",
    "path_traversal_probe",
    "open_redirect_probe",
    "crlf_injection_probe",
    "corsy_scan",
    "testssl_scan",
    "wpscan",
    "nuclei_scan",
    "http_request",
    "acl_bypass_probe",
    "actuator_probe",
    "jwt_crack",
    "openapi_fuzz",
})

_NON_REDUNDANT_REPEAT_TOOLS = frozenset({
    "log_note",
    "log_finding",
    "retract_finding",
})

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MAX_ZERO_YIELD_STREAK = 3


def normalize_dataset_formats(formats: str | Iterable[str] | None) -> List[str]:
    """Normalizes a format specification ('sft', 'dpo', 'checklist', 'all', or comma-separated) into a list."""
    if formats is None:
        return ["sft"]
    if isinstance(formats, str):
        raw_items = [item.strip().lower() for item in formats.split(",") if item.strip()]
    else:
        raw_items = [str(item).strip().lower() for item in formats if str(item).strip()]

    if not raw_items:
        return ["sft"]

    if "all" in raw_items:
        return ["sft", "dpo"]

    resolved: List[str] = []
    for fmt in raw_items:
        if fmt not in SUPPORTED_DATASET_FORMATS:
            raise ValueError(
                f"unsupported dataset format '{fmt}' -- supported: {', '.join(SUPPORTED_DATASET_FORMATS)}, all"
            )
        if fmt not in resolved:
            resolved.append(fmt)
    return resolved


def normalize_behaviors(behaviors: str | Iterable[str] | None) -> List[str]:
    """Normalizes and validates a behavior filter specification."""
    if behaviors is None:
        return []
    if isinstance(behaviors, str):
        raw_items = [item.strip().lower() for item in behaviors.split(",") if item.strip()]
    else:
        raw_items = [str(item).strip().lower() for item in behaviors if str(item).strip()]

    resolved: List[str] = []
    for b in raw_items:
        if b not in SUPPORTED_BEHAVIORS:
            raise ValueError(
                f"unknown behavior '{b}' -- supported: {', '.join(SUPPORTED_BEHAVIORS)}"
            )
        if b not in resolved:
            resolved.append(b)
    return resolved


def _normalize_profiles(profiles: str | Iterable[str] | None) -> List[str]:
    if profiles is None:
        return []
    if isinstance(profiles, str):
        return [p.strip().lower() for p in profiles.split(",") if p.strip()]
    return [str(p).strip().lower() for p in profiles if str(p).strip()]


def _index_legacy_tool_calls(trace_records: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Extracts ordered assistant tool_calls lists from subsequent request.messages,
    for trace records that only carry tool_call_names (not the full tool_calls payload)."""
    turns_tool_calls: List[List[Dict[str, Any]]] = []
    seen_sigs: set[str] = set()
    for rec in trace_records:
        msgs = (rec.get("request") or {}).get("messages") or []
        for msg in msgs:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") == "assistant" and msg.get("tool_calls"):
                tc_list = [tc for tc in (msg.get("tool_calls") or []) if isinstance(tc, dict)]
                sig = ",".join(str(tc.get("id") or "") for tc in tc_list)
                if sig and sig not in seen_sigs:
                    seen_sigs.add(sig)
                    turns_tool_calls.append(tc_list)
    return turns_tool_calls


def _build_assistant_message(
    rec: Dict[str, Any],
    fallback_tool_calls: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    msg: Dict[str, Any] = {
        "role": "assistant",
        "content": rec.get("content") or "",
    }
    reasoning = rec.get("reasoning_content")
    if reasoning is not None and str(reasoning).strip():
        msg["reasoning_content"] = str(reasoning)

    tool_calls = rec.get("tool_calls") or fallback_tool_calls or []
    if tool_calls:
        msg["tool_calls"] = copy.deepcopy(tool_calls)
    return msg


def _parse_tc_args(tc: Dict[str, Any]) -> Dict[str, Any]:
    fn = tc.get("function") or {}
    raw_args = fn.get("arguments") or "{}"
    if isinstance(raw_args, dict):
        return raw_args
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _canonical_tc_signature(tc: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Returns a canonical (tool_name, sorted_json_args) tuple for redundancy tracking,
    or None if the tool is legitimately repeatable (e.g. log_note, interactsh poll)."""
    fn = tc.get("function") or {}
    name = str(fn.get("name") or "")
    if not name or name in _NON_REDUNDANT_REPEAT_TOOLS:
        return None
    args = _parse_tc_args(tc)
    if name == "interactsh" and str(args.get("action") or "").lower() == "poll":
        return None
    return name, json.dumps(args, sort_keys=True)


def _extract_facts_lines_from_request(rec: Optional[Dict[str, Any]]) -> Set[str]:
    """Extracts the set of non-empty lines under `## Known Facts` from the trailing
    state message in `rec['request']['messages']`."""
    if not rec:
        return set()
    msgs = (rec.get("request") or {}).get("messages") or []
    if not msgs or not isinstance(msgs[-1], dict):
        return set()
    content = str(msgs[-1].get("content") or "")
    if "## Known Facts" not in content:
        return set()
    after_header = content.split("## Known Facts", 1)[1]
    facts_block = after_header.split("\n## ", 1)[0]
    lines: Set[str] = set()
    for raw_line in facts_block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("(") or line.startswith("---"):
            continue
        lines.add(line)
    return lines


def _compute_fact_delta(
    current_call: Dict[str, Any],
    next_call_group: Optional[List[Dict[str, Any]]],
) -> int:
    if not next_call_group:
        return 0
    before = _extract_facts_lines_from_request(current_call)
    after = _extract_facts_lines_from_request(next_call_group[0])
    return len(after - before)


def _has_dispatch_error(
    tool_calls: List[Dict[str, Any]],
    tool_results_by_call_id: Dict[str, Any],
) -> bool:
    for tc in tool_calls:
        fn = tc.get("function") or {}
        raw_args = fn.get("arguments") or "{}"
        if isinstance(raw_args, str):
            try:
                json.loads(raw_args)
            except Exception:
                return True
        cid = str(tc.get("id") or "")
        if cid and cid in tool_results_by_call_id:
            res = tool_results_by_call_id[cid]
            if isinstance(res, dict) and isinstance(res.get("error"), str):
                err_lower = res["error"].lower()
                if any(sub in err_lower for sub in _DISPATCH_ERROR_SUBSTRINGS):
                    return True
    return False


def _is_bad_finding_call(
    tc: Dict[str, Any],
    source: RunDatasetSource,
) -> Tuple[bool, Optional[str]]:
    """Returns (is_bad, reason) if `tc` is a `log_finding` call that was either
    unverified (no evidence_id), cited a hallucinated evidence_id, or was later retracted."""
    fn = tc.get("function") or {}
    if fn.get("name") != "log_finding":
        return False, None

    args = _parse_tc_args(tc)
    evidence_id = str(args.get("evidence_id") or "").strip()
    finding_text = str(args.get("finding") or "").strip()

    cid = str(tc.get("id") or "")
    res = source.tool_results_by_call_id.get(cid)
    finding_id: Optional[int] = None
    if isinstance(res, dict) and res.get("finding_id") is not None:
        try:
            finding_id = int(res["finding_id"])
        except (ValueError, TypeError):
            finding_id = None

    if finding_id is not None and finding_id in source.retracted_finding_ids:
        return True, "retracted_finding"
    if finding_text and finding_text in source.retracted_finding_texts:
        return True, "retracted_finding"
    if not evidence_id or (finding_id is not None and finding_id in source.unverified_finding_ids):
        return True, "unverified_finding"
    if source.valid_evidence_ids and evidence_id not in source.valid_evidence_ids:
        return True, "unverified_finding"
    return False, None


def _turn_was_nudged_next(
    next_call_group: Optional[List[Dict[str, Any]]],
) -> bool:
    """True if the immediately following turn's request messages contain a
    pre-finalization loop nudge ('Before finalizing: ...')."""
    if not next_call_group:
        return False
    first_next = next_call_group[0]
    msgs = (first_next.get("request") or {}).get("messages") or []
    for msg in reversed(msgs[:-1] if len(msgs) > 1 else msgs):
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = str(msg.get("content") or "")
            if content.startswith("Before finalizing:"):
                return True
            break
    return False


def _detect_unbacked_report_entities(
    report_text: str,
    source: RunDatasetSource,
) -> List[str]:
    """Detects CVEs or subdomains of `source.target` asserted in `report_text` that
    never appeared in `Known Facts`, `log.txt`, or tool outputs."""
    if not report_text or not report_text.strip():
        return []
    unbacked: List[str] = []

    # 1. Check CVEs mentioned in the final report against known_cves
    for cve in sorted({m.upper() for m in _CVE_RE.findall(report_text)}):
        if cve not in source.known_cves:
            unbacked.append(cve)

    # 2. Check any *.target subdomain mentioned in the final report
    apex = (source.target or "").strip().lower()
    if apex and "." in apex and not apex[0].isdigit():
        sub_re = re.compile(
            r"\b([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\."
            + re.escape(apex)
            + r")\b",
            re.IGNORECASE,
        )
        known_hosts_lower = {h.lower() for h in source.discovered_hosts} | {apex}
        # Also allow hosts that appeared anywhere in tool results
        raw_results_blob = json.dumps(source.tool_results_by_call_id).lower()
        for match in sorted({m.lower() for m in sub_re.findall(report_text)}):
            if match not in known_hosts_lower and match not in raw_results_blob:
                unbacked.append(match)

    return unbacked


def _detect_turn_behaviors_and_score(
    *,
    winning_call: Dict[str, Any],
    tool_calls: List[Dict[str, Any]],
    next_group: Optional[List[Dict[str, Any]]],
    source: RunDatasetSource,
    is_redundant: bool,
    has_dispatch_err: bool,
    has_bad_finding: bool,
    was_nudged_next: bool,
) -> Tuple[List[str], int, int]:
    """Computes (behaviors, score, fact_delta) for a single turn."""
    behaviors: Set[str] = set()
    fact_delta = _compute_fact_delta(winning_call, next_group)
    facts_before_text = "\n".join(_extract_facts_lines_from_request(winning_call))

    tc_names = [str((tc.get("function") or {}).get("name") or "") for tc in tool_calls]
    distinct_sigs = {
        sig for sig in (_canonical_tc_signature(tc) for tc in tool_calls) if sig is not None
    }

    # 1. recon_breadth
    if any(name in _RECON_BREADTH_TOOLS for name in tc_names):
        behaviors.add("recon_breadth")

    # 2. parallel_batching
    if len(distinct_sigs) >= 2 and not is_redundant and not has_dispatch_err:
        behaviors.add("parallel_batching")

    # 3. evidence_hydration
    if any(name in ("read_evidence", "search_evidence") for name in tc_names):
        behaviors.add("evidence_hydration")

    # 4. pivot_on_lead
    for tc in tool_calls:
        name = str((tc.get("function") or {}).get("name") or "")
        if name in _PIVOT_PROBE_TOOLS:
            args = _parse_tc_args(tc)
            target_arg = str(args.get("target") or args.get("host") or args.get("url") or "")
            if facts_before_text and target_arg:
                for host in source.discovered_hosts:
                    if host and host in target_arg and host in facts_before_text:
                        behaviors.add("pivot_on_lead")
                        break
                if "arjun_params_discovered" in facts_before_text or "params_discovered" in facts_before_text:
                    if "?" in target_arg or args.get("parameter") or args.get("param"):
                        behaviors.add("pivot_on_lead")

    # 5. evidence_discipline
    has_verified_finding = False
    for tc in tool_calls:
        name = str((tc.get("function") or {}).get("name") or "")
        if name == "log_finding" and not _is_bad_finding_call(tc, source)[0]:
            has_verified_finding = True
            behaviors.add("evidence_discipline")
        elif name == "log_note":
            behaviors.add("evidence_discipline")

    # 6. clean_reporting
    finish_reason = winning_call.get("finish_reason")
    content_str = (winning_call.get("content") or "").strip()
    unbacked_entities = _detect_unbacked_report_entities(content_str, source) if not tool_calls else []
    if (
        not tool_calls
        and finish_reason == "stop"
        and content_str
        and not was_nudged_next
        and not source.retracted_finding_ids
        and not source.unverified_finding_ids
        and not unbacked_entities
    ):
        behaviors.add("clean_reporting")

    score = 1
    if fact_delta > 0:
        score += 2
    if "evidence_hydration" in behaviors:
        score += 2
    if has_verified_finding:
        score += 2
    if "parallel_batching" in behaviors:
        score += 1
    if "pivot_on_lead" in behaviors:
        score += 1
    if "clean_reporting" in behaviors:
        score += 1
    if is_redundant or has_dispatch_err or has_bad_finding or was_nudged_next or unbacked_entities:
        score -= 3

    return sorted(behaviors), score, fact_delta


def _group_calls_by_turn(
    trace_records: List[Dict[str, Any]],
) -> List[Tuple[Tuple[int, str], List[Dict[str, Any]]]]:
    turns_map: Dict[Tuple[int, str], List[Dict[str, Any]]] = {}
    for rec in trace_records:
        t_num = int(rec.get("turn") or 0)
        c_kind = str(rec.get("call_kind") or "turn")
        turns_map.setdefault((t_num, c_kind), []).append(rec)
    return sorted(
        turns_map.items(),
        key=lambda item: (item[0][0], 0 if item[0][1] == "turn" else 1),
    )


def _resolve_turn_fallback_tcs(
    grouped_turns: List[Tuple[Tuple[int, str], List[Dict[str, Any]]]],
    trace_records: List[Dict[str, Any]],
) -> List[Optional[List[Dict[str, Any]]]]:
    legacy_tcs = _index_legacy_tool_calls(trace_records)
    legacy_idx = 0
    resolved: List[Optional[List[Dict[str, Any]]]] = []
    for _, call_group in grouped_turns:
        winning_call = call_group[-1]
        fallback_tcs: Optional[List[Dict[str, Any]]] = None
        if not winning_call.get("tool_calls") and winning_call.get("tool_call_names"):
            if legacy_idx < len(legacy_tcs):
                fallback_tcs = legacy_tcs[legacy_idx]
                legacy_idx += 1
        elif winning_call.get("tool_calls"):
            direct_ids = [str(tc.get("id") or "") for tc in winning_call.get("tool_calls") or []]
            if legacy_idx < len(legacy_tcs):
                leg_ids = [str(tc.get("id") or "") for tc in legacy_tcs[legacy_idx]]
                if direct_ids == leg_ids:
                    legacy_idx += 1
        resolved.append(fallback_tcs)
    return resolved


def evaluate_run_checklist(source: RunDatasetSource) -> Dict[str, Any]:
    """Evaluates a persisted engagement run across tool-conditioned checks (`PASS`,
    `FAIL`, `N/A`), 8 quantitative rubric dimensions (0.0-10.0), and automated
    root-cause diagnostics."""
    grouped_turns = _group_calls_by_turn(source.trace_records)
    fallback_tcs_by_turn = _resolve_turn_fallback_tcs(grouped_turns, source.trace_records)

    seen_sigs: Set[Tuple[str, str]] = set()
    redundant_turns_count = 0
    dispatch_error_turns_count = 0
    nudged_stops_count = 0
    evidence_reads_count = 0
    verified_findings_count = 0
    lead_pivot_count = 0
    positive_yield_turns = 0
    tool_calling_turns = 0
    total_tool_calls = 0
    current_zero_yield_streak = 0
    max_zero_yield_streak = 0
    recon_tools_used = False
    clean_final_stop = False
    final_report_text = ""

    probed_hosts: Set[str] = set()
    hallucinated_evidence_ids: List[str] = []
    diagnostics: List[Dict[str, Any]] = []

    last_interactsh_generate_turn: Optional[int] = None
    last_interactsh_poll_turn: Optional[int] = None

    # Track budget drift across all trace records
    max_budget_drift_ratio = 0.0
    total_llm_calls = len(source.trace_records)
    truncation_retries = sum(1 for r in source.trace_records if (r.get("truncation_attempt") or 0) > 0)
    for rec in source.trace_records:
        tb = rec.get("token_breakdown") or {}
        usage = rec.get("usage") or {}
        est = tb.get("estimated_prompt_total") or 0
        actual = usage.get("prompt_tokens") or 0
        if est > 0 and actual > 0:
            drift = abs(actual - est) / float(actual)
            if drift > max_budget_drift_ratio:
                max_budget_drift_ratio = drift

    offloaded_evidence_ids = {
        str(res["evidence_id"]).strip()
        for res in source.tool_results_by_call_id.values()
        if isinstance(res, dict) and res.get("evidence_id")
    }
    hydrated_evidence_targets: Set[str] = set()

    for idx, ((turn_num, _), call_group) in enumerate(grouped_turns):
        next_group = grouped_turns[idx + 1][1] if idx + 1 < len(grouped_turns) else None
        winning_call = call_group[-1]
        if winning_call.get("error") is not None or winning_call.get("finish_reason") == "length":
            continue

        assistant_msg = _build_assistant_message(winning_call, fallback_tcs_by_turn[idx])
        tool_calls = assistant_msg.get("tool_calls") or []
        content_str = (assistant_msg.get("content") or "").strip()

        if not tool_calls and _turn_was_nudged_next(next_group):
            nudged_stops_count += 1
            diagnostics.append({
                "check": "no_open_threads_at_stop",
                "status": "FAIL",
                "turn": turn_num,
                "category": "open_thread",
                "detail": f"Turn {turn_num} attempted to finalize early while open parameters or interactsh threads remained.",
            })
        elif not tool_calls and winning_call.get("finish_reason") == "stop" and content_str:
            clean_final_stop = True
            final_report_text = content_str

        has_dispatch_err = _has_dispatch_error(tool_calls, source.tool_results_by_call_id)
        if has_dispatch_err:
            dispatch_error_turns_count += 1
            diagnostics.append({
                "check": "no_dispatch_errors",
                "status": "FAIL",
                "turn": turn_num,
                "category": "contract_or_policy",
                "detail": f"Turn {turn_num} produced a tool dispatch or schema validation error.",
            })

        turn_sigs = [_canonical_tc_signature(tc) for tc in tool_calls]
        checkable_sigs = [s for s in turn_sigs if s is not None]
        is_redundant = bool(checkable_sigs and all(s in seen_sigs for s in checkable_sigs))
        if is_redundant:
            redundant_turns_count += 1
            diagnostics.append({
                "check": "no_redundant_loops",
                "status": "FAIL",
                "turn": turn_num,
                "category": "redundant_call",
                "detail": f"Turn {turn_num} repeated already-executed tool call signature(s): {[s[0] for s in checkable_sigs]}.",
            })
        for s in checkable_sigs:
            seen_sigs.add(s)

        has_bad_finding = any(_is_bad_finding_call(tc, source)[0] for tc in tool_calls)
        was_nudged_next = not tool_calls and _turn_was_nudged_next(next_group)
        turn_behaviors, _, fact_delta = _detect_turn_behaviors_and_score(
            winning_call=winning_call,
            tool_calls=tool_calls,
            next_group=next_group,
            source=source,
            is_redundant=is_redundant,
            has_dispatch_err=has_dispatch_err,
            has_bad_finding=has_bad_finding,
            was_nudged_next=was_nudged_next,
        )

        if "pivot_on_lead" in turn_behaviors:
            lead_pivot_count += 1

        if tool_calls:
            tool_calling_turns += 1
            total_tool_calls += len(tool_calls)

        turn_hydrated = False
        turn_logged_verified = False
        for tc in tool_calls:
            name = str((tc.get("function") or {}).get("name") or "")
            args = _parse_tc_args(tc)
            target_arg = str(args.get("target") or args.get("host") or args.get("url") or "")
            for host in source.discovered_hosts:
                if host and host in target_arg:
                    probed_hosts.add(host)
            if name in _RECON_BREADTH_TOOLS:
                recon_tools_used = True
            if name in ("read_evidence", "search_evidence"):
                evidence_reads_count += 1
                turn_hydrated = True
                t_tool = str(args.get("tool") or args.get("tool_id") or "")
                t_targ = str(args.get("target") or "")
                if t_tool and t_targ:
                    hydrated_evidence_targets.add(f"{t_tool}:{t_targ}")
            if name == "interactsh":
                action = str(args.get("action") or "").lower()
                if action == "generate":
                    last_interactsh_generate_turn = turn_num
                elif action == "poll":
                    last_interactsh_poll_turn = turn_num
            if name == "log_finding":
                ev_id = str(args.get("evidence_id") or "").strip()
                if ev_id and source.valid_evidence_ids and ev_id not in source.valid_evidence_ids:
                    hallucinated_evidence_ids.append(ev_id)
                if not _is_bad_finding_call(tc, source)[0]:
                    verified_findings_count += 1
                    turn_logged_verified = True

        if tool_calls:
            if fact_delta > 0 or turn_hydrated or turn_logged_verified:
                positive_yield_turns += 1
                current_zero_yield_streak = 0
            else:
                current_zero_yield_streak += 1
                if current_zero_yield_streak > max_zero_yield_streak:
                    max_zero_yield_streak = current_zero_yield_streak

    # Also mark hosts that have service/status/http records in facts_records as probed
    param_records_total = 0
    param_records_tested = 0
    tested_fields = (
        "sqli_tested",
        "sqli_injectable",
        "sqli_vulnerable",
        "xss_tested",
        "cmdi_tested",
        "open_redirect_tested",
        "open_redirect_vulnerable",
        "ssrf_tested",
        "ssrf_vulnerable",
        "nosql_tested",
        "nosql_vulnerable",
        "crlf_tested",
        "crlf_vulnerable",
        "arjun_tested",
    )
    for rec in source.facts_records:
        h = str(rec.get("host") or "")
        if h and any(k not in ("host", "port", "a_records") for k in rec.keys()):
            probed_hosts.add(h)
        if rec.get("arjun_params_discovered") or rec.get("params_discovered"):
            param_records_total += 1
            if any(rec.get(f) for f in tested_fields):
                param_records_tested += 1

    is_complement = (
        str(source.manifest.get("mode") or "").lower() == "complement"
        or bool(source.manifest.get("seed_from"))
        or _was_seeded(_extract_system_prompt(source.trace_records))
    )
    seed_respect_status = "N/A"
    if is_complement and grouped_turns:
        first_group = grouped_turns[0][1]
        first_msg = _build_assistant_message(first_group[-1], fallback_tcs_by_turn[0])
        first_tcs = first_msg.get("tool_calls") or []
        first_names = [str((tc.get("function") or {}).get("name") or "") for tc in first_tcs]
        if first_names and all(n in ("subfinder", "crtsh_lookup") for n in first_names):
            seed_respect_status = "FAIL"
            diagnostics.append({
                "check": "seed_respect",
                "status": "FAIL",
                "turn": 1,
                "category": "seed_context",
                "detail": "Complement-mode run spent Turn 1 re-running baseline subdomain discovery already covered by seed.",
            })
        else:
            seed_respect_status = "PASS"

    # Conditioned statuses ("PASS" | "FAIL" | "N/A")
    breadth_available = (
        not source.available_tools
        or bool(source.available_tools & _RECON_BREADTH_TOOLS)
    )
    recon_breadth_status = (
        "N/A"
        if not breadth_available
        else ("PASS" if (recon_tools_used or len(source.discovered_hosts) >= 1) else "FAIL")
    )

    host_coverage_ratio = (
        round(len(probed_hosts) / len(source.discovered_hosts), 4)
        if source.discovered_hosts
        else 1.0
    )
    host_coverage_status = (
        "N/A"
        if len(source.discovered_hosts) < 2
        else ("PASS" if host_coverage_ratio >= 0.8 else "FAIL")
    )
    if host_coverage_status == "FAIL":
        diagnostics.append({
            "check": "host_probing_coverage",
            "status": "FAIL",
            "turn": None,
            "category": "no_breadth_or_retrieval",
            "detail": f"Only {len(probed_hosts)}/{len(source.discovered_hosts)} discovered hosts were probed ({host_coverage_ratio:.0%}).",
        })

    injection_available = (
        not source.available_tools
        or bool(source.available_tools & _INJECTION_TOOLS)
    )
    param_followup_rate = (
        round(param_records_tested / param_records_total, 4)
        if param_records_total > 0
        else 1.0
    )
    param_followup_status = (
        "N/A"
        if (param_records_total == 0 or not injection_available)
        else ("PASS" if param_followup_rate >= 1.0 else "FAIL")
    )
    if param_followup_status == "FAIL":
        diagnostics.append({
            "check": "param_injection_followup",
            "status": "FAIL",
            "turn": None,
            "category": "missing_followup",
            "detail": f"Only {param_records_tested}/{param_records_total} host:port records with discovered parameters were injection-tested.",
        })

    interactsh_status = (
        "N/A"
        if last_interactsh_generate_turn is None
        else (
            "PASS"
            if (last_interactsh_poll_turn is not None and last_interactsh_poll_turn > last_interactsh_generate_turn)
            else "FAIL"
        )
    )

    unbacked_report_entities = _detect_unbacked_report_entities(final_report_text, source)
    retracted_leaked = [
        rt for rt in source.retracted_finding_texts
        if rt and final_report_text and rt.lower() in final_report_text.lower()
    ]
    report_confabulation_status = (
        "N/A"
        if not final_report_text
        else ("PASS" if (not unbacked_report_entities and not retracted_leaked) else "FAIL")
    )
    if report_confabulation_status == "FAIL":
        diagnostics.append({
            "check": "no_report_confabulation",
            "status": "FAIL",
            "turn": grouped_turns[-1][0][0] if grouped_turns else None,
            "category": "confabulation",
            "detail": f"Final report asserted unbacked entities {unbacked_report_entities} or leaked retracted findings {retracted_leaked}.",
        })

    has_provenance = bool(
        source.manifest.get("profile") is not None
        or "tool_ids" in source.manifest
    )
    evidence_hydration_status = (
        "N/A"
        if not offloaded_evidence_ids
        else ("PASS" if (evidence_reads_count > 0 or verified_findings_count > 0) else "FAIL")
    )
    hallucinated_ev_status = (
        "N/A"
        if not source.valid_evidence_ids
        else ("PASS" if not hallucinated_evidence_ids else "FAIL")
    )

    check_statuses: Dict[str, str] = {
        "clean_completion": "PASS" if (clean_final_stop and grouped_turns) else "FAIL",
        "tool_provenance_recorded": "PASS" if has_provenance else "FAIL",
        "recon_breadth": recon_breadth_status,
        "host_probing_coverage": host_coverage_status,
        "param_injection_followup": param_followup_status,
        "interactsh_polled": interactsh_status,
        "evidence_discipline": (
            "PASS"
            if (len(source.retracted_finding_ids) == 0 and len(source.unverified_finding_ids) == 0)
            else "FAIL"
        ),
        "no_hallucinated_evidence_ids": hallucinated_ev_status,
        "no_redundant_loops": "PASS" if redundant_turns_count == 0 else "FAIL",
        "no_tunnel_vision": "PASS" if max_zero_yield_streak <= MAX_ZERO_YIELD_STREAK else "FAIL",
        "no_dispatch_errors": "PASS" if dispatch_error_turns_count == 0 else "FAIL",
        "no_open_threads_at_stop": "PASS" if nudged_stops_count == 0 else "FAIL",
        "evidence_hydration": evidence_hydration_status,
        "no_report_confabulation": report_confabulation_status,
        "seed_respect": seed_respect_status,
    }

    # Boolean projection for backward compatibility ("PASS" or "N/A" -> True, "FAIL" -> False)
    checks: Dict[str, bool] = {
        k: (status != "FAIL") for k, status in check_statuses.items()
    }

    applicable_statuses = [s for s in check_statuses.values() if s != "N/A"]
    passed_applicable = sum(1 for s in applicable_statuses if s == "PASS")
    checklist_score = (
        round(passed_applicable / len(applicable_statuses), 4)
        if applicable_statuses
        else 0.0
    )

    # Quantitative ratios
    truncation_retry_rate = round(truncation_retries / total_llm_calls, 4) if total_llm_calls else 0.0
    parallelism_ratio = round(total_tool_calls / tool_calling_turns, 4) if tool_calling_turns else 0.0
    redundancy_rate = round(redundant_turns_count / tool_calling_turns, 4) if tool_calling_turns else 0.0
    dispatch_error_rate = round(dispatch_error_turns_count / tool_calling_turns, 4) if tool_calling_turns else 0.0
    fact_yield_rate = round(positive_yield_turns / tool_calling_turns, 4) if tool_calling_turns else 0.0
    evidence_hydration_rate = (
        round(min(1.0, evidence_reads_count / len(offloaded_evidence_ids)), 4)
        if offloaded_evidence_ids
        else 1.0
    )
    total_logged_findings = (
        verified_findings_count
        + len(source.retracted_finding_ids)
        + len(source.unverified_finding_ids)
    )
    verified_finding_rate = (
        round(verified_findings_count / total_logged_findings, 4)
        if total_logged_findings > 0
        else 1.0
    )

    # 8-Dimension Rubric Scores (0.0 - 10.0)
    scores: Dict[str, float] = {
        "context_management": round(
            max(
                0.0,
                10.0
                - (4.0 if check_statuses["clean_completion"] == "FAIL" else 0.0)
                - min(3.0, truncation_retry_rate * 10.0)
                - (3.0 if max_budget_drift_ratio > 0.15 else 0.0),
            ),
            2,
        ),
        "retrieval": round(
            max(
                0.0,
                10.0
                - (5.0 if check_statuses["evidence_hydration"] == "FAIL" else 0.0)
                - (5.0 if check_statuses["no_hallucinated_evidence_ids"] == "FAIL" else 0.0),
            ),
            2,
        ),
        "recon_width": round(
            max(
                0.0,
                10.0
                - (5.0 if check_statuses["recon_breadth"] == "FAIL" else 0.0)
                - (5.0 * (1.0 - host_coverage_ratio) if check_statuses["host_probing_coverage"] != "N/A" else 0.0),
            ),
            2,
        ),
        "recon_depth": round(
            max(
                0.0,
                10.0
                - (4.0 * (1.0 - param_followup_rate) if check_statuses["param_injection_followup"] != "N/A" else 0.0)
                - (3.0 if check_statuses["interactsh_polled"] == "FAIL" else 0.0)
                - (3.0 if check_statuses["no_open_threads_at_stop"] == "FAIL" else 0.0),
            ),
            2,
        ),
        "tool_usage": round(
            max(
                0.0,
                10.0
                - min(4.0, redundancy_rate * 10.0)
                - min(4.0, dispatch_error_rate * 10.0)
                - (2.0 if (tool_calling_turns > 0 and parallelism_ratio < 1.2) else 0.0),
            ),
            2,
        ),
        "evidence_discipline": round(
            max(
                0.0,
                10.0 * verified_finding_rate
                - (2.0 * len(source.unverified_finding_ids))
                - (2.0 * len(source.retracted_finding_ids)),
            ),
            2,
        ),
        "pivoting": round(
            max(
                0.0,
                10.0
                - (4.0 if check_statuses["no_tunnel_vision"] == "FAIL" else 0.0)
                - (3.0 if check_statuses["seed_respect"] == "FAIL" else 0.0)
                - (3.0 if (tool_calling_turns > 1 and fact_yield_rate < 0.3) else 0.0),
            ),
            2,
        ),
        "reporting_quality": round(
            max(
                0.0,
                10.0
                - (5.0 if check_statuses["clean_completion"] == "FAIL" else 0.0)
                - (5.0 if check_statuses["no_report_confabulation"] == "FAIL" else 0.0),
            ),
            2,
        ),
    }
    overall_score = round(sum(scores.values()) / len(scores), 2)

    critical_passed = (
        checks["clean_completion"]
        and checks["evidence_discipline"]
        and checks["no_redundant_loops"]
        and checks["no_dispatch_errors"]
        and checks["no_report_confabulation"]
    )

    return {
        "run_id": source.run_id,
        "target": source.target,
        "profile": source.manifest.get("profile"),
        "guidance": source.manifest.get("guidance") or None,
        "allow_destructive": bool(source.manifest.get("allow_destructive", False)),
        "passed": critical_passed,
        "checklist_score": checklist_score,
        "overall_score": overall_score,
        "scores": scores,
        "checks": checks,
        "check_statuses": check_statuses,
        "diagnostics": diagnostics,
        "metrics": {
            "turns_count": len(grouped_turns),
            "tool_calling_turns": tool_calling_turns,
            "total_tool_calls": total_tool_calls,
            "parallelism_ratio": parallelism_ratio,
            "discovered_hosts_count": len(source.discovered_hosts),
            "probed_hosts_count": len(probed_hosts),
            "host_probing_coverage": host_coverage_ratio,
            "param_injection_followup_rate": param_followup_rate,
            "verified_findings_count": verified_findings_count,
            "retracted_findings_count": len(source.retracted_finding_ids),
            "unverified_findings_count": len(source.unverified_finding_ids),
            "verified_finding_rate": verified_finding_rate,
            "redundant_turns_count": redundant_turns_count,
            "redundancy_rate": redundancy_rate,
            "dispatch_error_turns_count": dispatch_error_turns_count,
            "dispatch_error_rate": dispatch_error_rate,
            "nudged_stops_count": nudged_stops_count,
            "evidence_reads_count": evidence_reads_count,
            "evidence_hydration_rate": evidence_hydration_rate,
            "lead_pivot_count": lead_pivot_count,
            "fact_yield_rate": fact_yield_rate,
            "max_zero_yield_streak": max_zero_yield_streak,
            "budget_drift_ratio": round(max_budget_drift_ratio, 4),
            "truncation_retry_rate": truncation_retry_rate,
            "unbacked_report_entities": unbacked_report_entities,
            "hallucinated_evidence_ids": hallucinated_evidence_ids,
        },
    }


def extract_sft_records(
    source: RunDatasetSource,
    *,
    filter_quality: bool = True,
    require_reasoning: bool = False,
    scrub: bool = False,
    behaviors: str | Iterable[str] | None = None,
    min_score: Optional[int] = None,
    deduplicate: bool = False,
) -> List[Dict[str, Any]]:
    """Extracts per-turn SFT records from a single engagement run, with optional
    behavioral filtering, minimum score threshold, and signature deduplication."""
    required_behaviors = set(normalize_behaviors(behaviors))
    scrub_patterns = _build_scrub_patterns(source) if scrub else []
    grouped_turns = _group_calls_by_turn(source.trace_records)
    fallback_tcs_by_turn = _resolve_turn_fallback_tcs(grouped_turns, source.trace_records)

    seen_call_sigs: Set[Tuple[str, str]] = set()
    seen_dedup_keys: Set[Tuple[Tuple[str, ...], Tuple[str, ...]]] = set()
    sft_records: List[Dict[str, Any]] = []
    zero_yield_streak = 0

    for idx, ((turn_num, call_kind), call_group) in enumerate(grouped_turns):
        next_group = grouped_turns[idx + 1][1] if idx + 1 < len(grouped_turns) else None
        winning_call = call_group[-1]
        fallback_tcs = fallback_tcs_by_turn[idx]

        if winning_call.get("error") is not None:
            continue
        if winning_call.get("finish_reason") == "length":
            continue

        assistant_msg = _build_assistant_message(winning_call, fallback_tcs)
        tool_calls = assistant_msg.get("tool_calls") or []
        content_str = (assistant_msg.get("content") or "").strip()
        if not content_str and not tool_calls:
            continue

        # Check redundancy against prior turns before registering this turn's calls
        turn_sigs = [_canonical_tc_signature(tc) for tc in tool_calls]
        checkable_sigs = [s for s in turn_sigs if s is not None]
        is_redundant = bool(checkable_sigs and all(s in seen_call_sigs for s in checkable_sigs))
        for s in checkable_sigs:
            seen_call_sigs.add(s)

        has_dispatch_err = _has_dispatch_error(tool_calls, source.tool_results_by_call_id)
        has_bad_finding = any(_is_bad_finding_call(tc, source)[0] for tc in tool_calls)
        was_nudged_next = not tool_calls and _turn_was_nudged_next(next_group)
        unbacked_report = _detect_unbacked_report_entities(content_str, source) if not tool_calls else []

        turn_behaviors, turn_score, fact_delta = _detect_turn_behaviors_and_score(
            winning_call=winning_call,
            tool_calls=tool_calls,
            next_group=next_group,
            source=source,
            is_redundant=is_redundant,
            has_dispatch_err=has_dispatch_err,
            has_bad_finding=has_bad_finding,
            was_nudged_next=was_nudged_next,
        )

        if tool_calls:
            if (
                fact_delta > 0
                or "evidence_hydration" in turn_behaviors
                or "evidence_discipline" in turn_behaviors
            ):
                zero_yield_streak = 0
            else:
                zero_yield_streak += 1

        in_tunnel_vision = zero_yield_streak > MAX_ZERO_YIELD_STREAK

        if require_reasoning and not (assistant_msg.get("reasoning_content") or "").strip():
            continue

        if filter_quality:
            if (
                is_redundant
                or has_dispatch_err
                or has_bad_finding
                or was_nudged_next
                or in_tunnel_vision
                or bool(unbacked_report)
            ):
                continue

        if required_behaviors and not (required_behaviors & set(turn_behaviors)):
            continue

        if min_score is not None and turn_score < min_score:
            continue

        tc_names = tuple(winning_call.get("tool_call_names") or [])
        if deduplicate and fact_delta == 0 and tc_names:
            dedup_key = (tc_names, tuple(turn_behaviors))
            if dedup_key in seen_dedup_keys:
                continue
            seen_dedup_keys.add(dedup_key)

        req = winning_call.get("request") or {}
        req_messages = copy.deepcopy(req.get("messages") or [])
        req_tools = copy.deepcopy(req.get("tools") or [])
        usage = winning_call.get("usage") or {}

        record: Dict[str, Any] = {
            "id": f"{source.run_id}:turn_{turn_num}:{call_kind}",
            "run_id": source.run_id,
            "target": source.target,
            "turn": turn_num,
            "call_kind": call_kind,
            "messages": [*req_messages, assistant_msg],
            "tools": req_tools,
            "metadata": {
                "model": req.get("model") or source.manifest.get("model") or "",
                "profile": source.manifest.get("profile"),
                "guidance": source.manifest.get("guidance") or None,
                "allow_destructive": bool(source.manifest.get("allow_destructive", False)),
                "finish_reason": winning_call.get("finish_reason"),
                "tool_call_names": list(tc_names),
                "behaviors": turn_behaviors,
                "score": turn_score,
                "fact_delta": fact_delta,
                "is_redundant": is_redundant,
                "prompt_tokens": usage.get("prompt_tokens") or 0,
                "completion_tokens": usage.get("completion_tokens") or 0,
            },
        }
        if scrub_patterns:
            record = apply_scrub_map(record, scrub_patterns)
        sft_records.append(record)

    return sft_records


def extract_dpo_records(
    source: RunDatasetSource,
    *,
    scrub: bool = False,
) -> List[Dict[str, Any]]:
    """Extracts natural DPO / preference contrast pairs from an engagement run:
    1. `truncation_retry`: truncated completion vs. clean retry on the same turn.
    2. `open_thread_nudge`: premature final report stop vs. post-nudge investigation tool call.
    3. `retracted_finding` / `unverified_finding`: premature `log_finding` vs. `log_note` hypothesis.
    4. `redundant_tool_call`: duplicate repeat tool call vs. subsequent non-redundant pivot.
    """
    scrub_patterns = _build_scrub_patterns(source) if scrub else []
    grouped_turns = _group_calls_by_turn(source.trace_records)
    resolved_group_tcs = _resolve_turn_fallback_tcs(grouped_turns, source.trace_records)
    dpo_records: List[Dict[str, Any]] = []
    seen_call_sigs: Set[Tuple[str, str]] = set()

    for idx, ((turn_num, call_kind), call_group) in enumerate(grouped_turns):
        winning_call = call_group[-1]
        if winning_call.get("error") is not None or winning_call.get("finish_reason") == "length":
            continue

        fallback_tcs = resolved_group_tcs[idx]
        winning_msg = _build_assistant_message(winning_call, fallback_tcs)
        req = winning_call.get("request") or {}
        prompt_messages = copy.deepcopy(req.get("messages") or [])
        prompt_tools = copy.deepcopy(req.get("tools") or [])

        # 1. Truncation retry contrast pair
        if len(call_group) > 1:
            for attempt_rec in call_group[:-1]:
                if attempt_rec.get("finish_reason") == "length":
                    rejected_msg = _build_assistant_message(attempt_rec)
                    pair = {
                        "id": f"{source.run_id}:turn_{turn_num}:truncation_retry_{attempt_rec.get('index', 0)}",
                        "run_id": source.run_id,
                        "target": source.target,
                        "turn": turn_num,
                        "reason": "truncation_retry",
                        "prompt": copy.deepcopy(prompt_messages),
                        "tools": copy.deepcopy(prompt_tools),
                        "chosen": copy.deepcopy(winning_msg),
                        "rejected": rejected_msg,
                    }
                    if scrub_patterns:
                        pair = apply_scrub_map(pair, scrub_patterns)
                    dpo_records.append(pair)

        # 2. Premature stop vs. post-nudge continuation
        next_group = grouped_turns[idx + 1][1] if idx + 1 < len(grouped_turns) else None
        if not (winning_msg.get("tool_calls") or []) and _turn_was_nudged_next(next_group):
            assert next_group is not None
            next_winning = next_group[-1]
            next_fallback_tcs = resolved_group_tcs[idx + 1]
            if next_winning.get("error") is None and next_winning.get("finish_reason") != "length":
                next_msg = _build_assistant_message(next_winning, next_fallback_tcs)
                if next_msg.get("tool_calls"):
                    pair = {
                        "id": f"{source.run_id}:turn_{turn_num}:open_thread_nudge",
                        "run_id": source.run_id,
                        "target": source.target,
                        "turn": turn_num,
                        "reason": "open_thread_nudge",
                        "prompt": copy.deepcopy(prompt_messages),
                        "tools": copy.deepcopy(prompt_tools),
                        "chosen": next_msg,
                        "rejected": copy.deepcopy(winning_msg),
                    }
                    if scrub_patterns:
                        pair = apply_scrub_map(pair, scrub_patterns)
                    dpo_records.append(pair)

        # 3. Retracted or unverified finding -> log_note contrast pair
        tool_calls = winning_msg.get("tool_calls") or []
        bad_reasons: List[str] = []
        rewritten_tcs: List[Dict[str, Any]] = []
        for tc in tool_calls:
            is_bad, bad_reason = _is_bad_finding_call(tc, source)
            if is_bad and bad_reason:
                bad_reasons.append(bad_reason)
                args = _parse_tc_args(tc)
                finding_text = str(args.get("finding") or "").strip()
                rewritten_tc = copy.deepcopy(tc)
                rewritten_tc["function"] = {
                    "name": "log_note",
                    "arguments": json.dumps({"note": finding_text}),
                }
                rewritten_tcs.append(rewritten_tc)
            else:
                rewritten_tcs.append(copy.deepcopy(tc))

        if bad_reasons:
            chosen_msg = copy.deepcopy(winning_msg)
            chosen_msg["tool_calls"] = rewritten_tcs
            primary_reason = (
                "retracted_finding" if "retracted_finding" in bad_reasons else bad_reasons[0]
            )
            pair = {
                "id": f"{source.run_id}:turn_{turn_num}:{primary_reason}",
                "run_id": source.run_id,
                "target": source.target,
                "turn": turn_num,
                "reason": primary_reason,
                "prompt": copy.deepcopy(prompt_messages),
                "tools": copy.deepcopy(prompt_tools),
                "chosen": chosen_msg,
                "rejected": copy.deepcopy(winning_msg),
            }
            if scrub_patterns:
                pair = apply_scrub_map(pair, scrub_patterns)
            dpo_records.append(pair)

        # 4. Redundant repeat tool call vs. next clean non-redundant tool call
        turn_sigs = [_canonical_tc_signature(tc) for tc in tool_calls]
        checkable_sigs = [s for s in turn_sigs if s is not None]
        is_redundant = bool(checkable_sigs and all(s in seen_call_sigs for s in checkable_sigs))
        for s in checkable_sigs:
            seen_call_sigs.add(s)

        if is_redundant:
            for future_idx in range(idx + 1, len(grouped_turns)):
                future_winning = grouped_turns[future_idx][1][-1]
                if future_winning.get("error") is not None or future_winning.get("finish_reason") == "length":
                    continue
                future_msg = _build_assistant_message(future_winning, resolved_group_tcs[future_idx])
                future_tcs = future_msg.get("tool_calls") or []
                if not future_tcs:
                    continue
                if _has_dispatch_error(future_tcs, source.tool_results_by_call_id):
                    continue
                if any(_is_bad_finding_call(tc, source)[0] for tc in future_tcs):
                    continue
                future_sigs = [s for s in (_canonical_tc_signature(tc) for tc in future_tcs) if s is not None]
                if future_sigs and not all(s in seen_call_sigs for s in future_sigs):
                    pair = {
                        "id": f"{source.run_id}:turn_{turn_num}:redundant_tool_call",
                        "run_id": source.run_id,
                        "target": source.target,
                        "turn": turn_num,
                        "reason": "redundant_tool_call",
                        "prompt": copy.deepcopy(prompt_messages),
                        "tools": copy.deepcopy(prompt_tools),
                        "chosen": future_msg,
                        "rejected": copy.deepcopy(winning_msg),
                    }
                    if scrub_patterns:
                        pair = apply_scrub_map(pair, scrub_patterns)
                    dpo_records.append(pair)
                    break

    return dpo_records


def build_datasets_from_sources(
    sources: Iterable[RunDatasetSource],
    *,
    formats: str | Iterable[str] | None = "sft",
    filter_quality: bool = True,
    require_reasoning: bool = False,
    scrub: bool = False,
    behaviors: str | Iterable[str] | None = None,
    profiles: str | Iterable[str] | None = None,
    min_score: Optional[int] = None,
    min_checklist_score: Optional[float] = None,
    deduplicate: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """Builds requested dataset formats ('sft', 'dpo', 'checklist') across one or more RunDatasetSource objects."""
    normalized = normalize_dataset_formats(formats)
    allowed_profiles = set(_normalize_profiles(profiles))
    results: Dict[str, List[Dict[str, Any]]] = {fmt: [] for fmt in normalized}

    for source in sources:
        if allowed_profiles:
            run_profile = str(source.manifest.get("profile") or "").strip().lower()
            if run_profile not in allowed_profiles:
                continue

        checklist_eval = evaluate_run_checklist(source)
        if min_checklist_score is not None and checklist_eval["checklist_score"] < min_checklist_score:
            continue

        if "checklist" in results:
            entry = copy.deepcopy(checklist_eval)
            if scrub:
                entry = apply_scrub_map(entry, _build_scrub_patterns(source))
            results["checklist"].append(entry)

        if "sft" in results:
            results["sft"].extend(
                extract_sft_records(
                    source,
                    filter_quality=filter_quality,
                    require_reasoning=require_reasoning,
                    scrub=scrub,
                    behaviors=behaviors,
                    min_score=min_score,
                    deduplicate=deduplicate,
                )
            )
        if "dpo" in results:
            results["dpo"].extend(
                extract_dpo_records(
                    source,
                    scrub=scrub,
                )
            )
    return results


def write_datasets(
    datasets: Dict[str, List[Dict[str, Any]]],
    *,
    output_path: Optional[str | Path] = None,
    default_dir: Optional[Path] = None,
) -> Dict[str, Path]:
    """Writes extracted JSONL datasets to disk with 0o600 permissions.

    - If `output_path` is a single file path and only 1 format was requested, writes directly there.
    - If `output_path` is a directory (or multiple formats were requested), writes `dataset_<fmt>.jsonl`.
    - If `output_path` is None, writes `dataset_<fmt>.jsonl` inside `default_dir` (or current working directory).
    """
    written: Dict[str, Path] = {}
    formats = list(datasets.keys())
    base_dir = default_dir or Path.cwd()

    for fmt, records in datasets.items():
        if output_path is None:
            dest = base_dir / f"dataset_{fmt}.jsonl"
        else:
            out_p = Path(output_path)
            if len(formats) == 1 and not out_p.is_dir() and out_p.suffix in (".jsonl", ".json"):
                dest = out_p
            elif out_p.suffix in (".jsonl", ".json") and len(formats) > 1:
                dest = out_p.with_name(f"{out_p.stem}_{fmt}{out_p.suffix}")
            else:
                dest = out_p / f"dataset_{fmt}.jsonl"

        dest.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        written[fmt] = dest

    return written
