"""Pure benchmark scoring (Tradecraft 2.0, Phase 0).

The metric that keeps every later optimization honest:

    matched_expected / total_expected   -- recall against a lab target's
                                           known ground truth
    turns_used, tokens                  -- what the engagement cost

A lab config declares expected findings as keyword groups (all keywords
of a group must appear in some logged finding for that group to count).
Keyword matching is deliberately simple: the ground truth of a lab
target (Juice Shop, DVWA, ...) is known, and a finding that found the
thing names the thing. Anything smarter (LLM-judged scoring) belongs
behind this same interface later, not in v1.
"""
from __future__ import annotations

from typing import Any, Dict, List


def _finding_matches(finding: str, keywords: List[str]) -> bool:
    lowered = finding.lower()
    return all(k.lower() in lowered for k in keywords)


def score_findings(
    findings: List[str],
    expected: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """expected: [{"id": str, "keywords": [str, ...]}, ...].

    Returns {matched: [...], missed: [...], recall: float, matched_ids}."""
    matched: List[Dict[str, Any]] = []
    missed: List[Dict[str, Any]] = []
    matched_ids = []
    for item in expected:
        keywords = item.get("keywords") or []
        hit = any(_finding_matches(f, keywords) for f in findings)
        entry = {"id": item.get("id"), "keywords": keywords}
        if hit:
            matched.append(entry)
            if item.get("id") is not None:
                matched_ids.append(item["id"])
        else:
            missed.append(entry)
    total = len(expected)
    recall = (len(matched) / total) if total else 0.0
    return {
        "matched": matched,
        "missed": missed,
        "matched_ids": matched_ids,
        "recall": recall,
        "total_expected": total,
    }


def efficiency(
    recall: float,
    turns_used: int,
    findings_count: int,
) -> Dict[str, float]:
    """The two numbers to track across refactors: recall (quality) and
    turns-per-recall-point (cost). Findings-per-turn measures how
    conversational the engagement was."""
    return {
        "recall": recall,
        "turns_used": turns_used,
        "findings_per_turn": (findings_count / turns_used) if turns_used else 0.0,
        "turns_per_recall_point": (turns_used / recall) if recall > 0 else 0.0,
    }


def render_summary(results: List[Dict[str, Any]]) -> str:
    """Markdown bench report: one row per lab, plus totals."""
    if not results:
        return "_(no bench results)_"
    lines = [
        "| Lab | Recall | Expected | Matched | Turns | Findings |",
        "|---|---|---|---|---|---|",
    ]
    total_recall = 0.0
    for r in results:
        recall = r.get("recall", 0.0)
        total_recall += recall
        lines.append(
            f"| {r.get('lab', '?')} | {recall:.0%} | {r.get('total_expected', 0)} "
            f"| {len(r.get('matched', []))} | {r.get('turns_used', 0)} "
            f"| {r.get('findings_count', 0)} |"
        )
    lines.append("")
    if results:
        lines.append(f"**Mean recall: {total_recall / len(results):.0%}**")
    lines.append("")
    for r in results:
        missed = r.get("missed") or []
        if missed:
            ids = ", ".join(str(m.get("id")) for m in missed)
            lines.append(f"- missed in {r.get('lab', '?')}: {ids}")
    return "\n".join(lines)
