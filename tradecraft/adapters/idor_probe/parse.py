"""
Parsing and differential analysis logic for idor_probe.
Pure functions -- no I/O, no subprocess, no network.
"""
from __future__ import annotations

import difflib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from tradecraft.adapters.idor_probe.execute import RawHttpResponse, RawIdorResult

IGNORE_DYNAMIC_KEYS = {
    "timestamp", "time", "date", "datetime", "nonce", "csrf", "_csrf",
    "token", "_token", "authenticity_token", "request_id", "execution_time",
    "duration", "trace_id", "session_id", "sid",
}

SOFT_404_MARKERS = (
    "not found", "não encontrado", "nenhum registro", "invalid id",
    "does not exist", "registro não localizado", "object not found",
    "user not found", "pedido não encontrado", "documento não encontrado",
    "item not found", "error 404", "página não encontrada", "no results",
    "record not found",
)


def compute_similarity(text_a: str, text_b: str) -> float:
    if text_a == text_b:
        return 1.0
    if not text_a or not text_b:
        return 0.0
    # Bound to first 10,000 characters for instant computation
    sample_a = text_a[:10000]
    sample_b = text_b[:10000]
    return round(difflib.SequenceMatcher(None, sample_a, sample_b).quick_ratio(), 3)


def is_soft_404(status_code: int, body: str, baseline_body: str) -> bool:
    if status_code != 200:
        return False
    body_lower = body.lower().strip()
    if not body_lower:
        return True

    try:
        data = json.loads(body)
        if isinstance(data, dict):
            if data.get("error") or data.get("errors") or data.get("success") is False:
                return True
            if "data" in data and (data["data"] is None or data["data"] == []):
                # If baseline had real data and candidate has null/empty data
                return True
    except Exception:
        pass

    if len(body_lower) < 500:
        if any(marker in body_lower for marker in SOFT_404_MARKERS):
            return True

    return False


def _flatten_json(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten_json(v, full_key))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:5]):  # inspect first 5 items
            full_key = f"{prefix}[{idx}]"
            out.update(_flatten_json(item, full_key))
    else:
        out[prefix] = obj
    return out


def extract_json_diff(
    baseline_text: str,
    candidate_text: str,
    max_chars: int = 1000,
) -> Tuple[bool, List[str], str]:
    try:
        base_obj = json.loads(baseline_text)
        cand_obj = json.loads(candidate_text)
    except Exception:
        return (False, [], "")

    flat_base = _flatten_json(base_obj)
    flat_cand = _flatten_json(cand_obj)

    all_keys = set(flat_base.keys()) | set(flat_cand.keys())
    differing_keys: List[str] = []
    diff_entries: Dict[str, Any] = {}

    for k in sorted(all_keys):
        key_leaf = k.split(".")[-1].split("[")[0].lower()
        if key_leaf in IGNORE_DYNAMIC_KEYS:
            continue

        val_base = flat_base.get(k)
        val_cand = flat_cand.get(k)

        if val_base != val_cand:
            differing_keys.append(k)
            if len(diff_entries) < 15:
                diff_entries[k] = {"baseline": val_base, "candidate": val_cand}

    if not differing_keys:
        return (True, [], "")

    preview = json.dumps(diff_entries, indent=2, ensure_ascii=False)
    if len(preview) > max_chars:
        preview = preview[:max_chars] + "\n... [diff truncated]"

    return (True, differing_keys, preview)


def extract_html_diff(
    baseline_text: str,
    candidate_text: str,
    max_chars: int = 1000,
) -> Tuple[List[str], str]:
    base_lines = {l.strip() for l in baseline_text.splitlines() if l.strip()}
    cand_lines = [l.strip() for l in candidate_text.splitlines() if l.strip()]

    candidate_unique: List[str] = []
    ignorable_tags = {"</div>", "</td>", "</tr>", "</ul>", "</ol>", "</p>", "</span>", "</body>", "</html>", "<br>", "<hr>"}

    for line in cand_lines:
        if line in base_lines:
            continue
        if line.lower() in ignorable_tags:
            continue
        line_lower = line.lower()
        if any(marker in line_lower for marker in ("csrf", "authenticity_token", "nonce", "_token")):
            continue
        if re.search(r"\b202[0-9]-[0-9]{2}-[0-9]{2}\b", line_lower):
            continue

        if line not in candidate_unique:
            candidate_unique.append(line)

    if not candidate_unique:
        return ([], "")

    sample_lines = candidate_unique[:10]
    preview = "\n".join(sample_lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars] + "\n... [diff truncated]"

    return (candidate_unique, preview)


def classify_probe(
    probe: RawHttpResponse,
    baseline: RawHttpResponse,
    similarity: float,
    has_meaningful_diff: bool,
    is_soft404: bool,
) -> str:
    if probe.error:
        return "network_error"
    if probe.status_code in (401, 403):
        return "auth_required"
    if probe.status_code == 404:
        return "not_found"
    if probe.status_code >= 500:
        return "server_error"
    if probe.body == baseline.body or similarity >= 0.999:
        return "identical"
    if is_soft404:
        return "soft_404_or_error"

    if probe.status_code == 200:
        if has_meaningful_diff and similarity < 0.99:
            return "distinct_object_candidate"
        return "negligible_diff"

    return "unclassified"


def parse_result(raw: RawIdorResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    baseline = raw.baseline_response
    if not baseline:
        return {"target": raw.target, "error": "No baseline response recorded"}

    parsed_probes: List[Dict[str, Any]] = []
    distinct_candidates = 0

    for probe in raw.probes:
        if probe.error:
            parsed_probes.append({
                "candidate_id": probe.tested_id,
                "url": probe.url,
                "status_code": 0,
                "classification": "network_error",
                "error": probe.error,
            })
            continue

        sim = compute_similarity(baseline.body, probe.body)
        soft404 = is_soft_404(probe.status_code, probe.body, baseline.body)

        is_json, diff_keys, json_preview = extract_json_diff(baseline.body, probe.body)
        if is_json:
            has_diff = bool(diff_keys)
            diff_preview = json_preview
        else:
            cand_unique, html_preview = extract_html_diff(baseline.body, probe.body)
            has_diff = bool(cand_unique)
            diff_preview = html_preview
            diff_keys = []

        classification = classify_probe(
            probe=probe,
            baseline=baseline,
            similarity=sim,
            has_meaningful_diff=has_diff,
            is_soft404=soft404,
        )

        if classification == "distinct_object_candidate":
            distinct_candidates += 1

        length_delta = probe.body_length - baseline.body_length
        probe_entry: Dict[str, Any] = {
            "candidate_id": probe.tested_id,
            "url": probe.url,
            "status_code": probe.status_code,
            "status_diff": f"{baseline.status_code} -> {probe.status_code}",
            "body_length": probe.body_length,
            "length_delta": f"{'+' if length_delta > 0 else ''}{length_delta}B",
            "similarity_ratio": sim,
            "classification": classification,
            "diff_preview": diff_preview,
        }
        if diff_keys:
            probe_entry["differing_keys"] = diff_keys[:10]

        parsed_probes.append(probe_entry)

    potential_idor = distinct_candidates > 0
    if potential_idor:
        summary = (
            f"Tested {len(raw.probes)} candidate ID(s) against baseline '{raw.baseline_id}' (HTTP {baseline.status_code}). "
            f"{distinct_candidates} candidate(s) returned HTTP 200 with distinct object content. "
            "Inspect diff_preview to evaluate whether sensitive user/account/business data is exposed."
        )
    else:
        summary = (
            f"Tested {len(raw.probes)} candidate ID(s) against baseline '{raw.baseline_id}' (HTTP {baseline.status_code}). "
            "No unauthorized distinct objects observed (responses were identical, errors, or 404/403)."
        )

    return {
        "target": raw.target,
        "param": raw.param,
        "baseline": {
            "value": raw.baseline_id,
            "status_code": baseline.status_code,
            "body_length": baseline.body_length,
            "url": baseline.url,
        },
        "total_probes": len(raw.probes),
        "potential_idor_detected": potential_idor,
        "summary": summary,
        "probes": parsed_probes,
    }
