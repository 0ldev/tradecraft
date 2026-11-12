"""Engagement fan-out (Tradecraft 2.0, Phase 4).

Splits one engagement across per-target focused sub-runs instead of
forcing one ever-growing conversation to cover every host:port.

Why: a single loop's context grows with EVERY tool result from EVERY
target, so breadth costs context linearly and the model's per-turn
attention degrades. A focused sub-run sees only its own target's facts,
only the tools relevant to that group, and a seed line saying exactly
what's already known about its target -- small context, dense signal.

The planner here is deterministic (coverage-matrix driven); each
sub-run is a real engagement loop (execution/loop.run_engagement) with
its own memory, facts, and evidence. The merge step is likewise
deterministic: sub-run findings + facts are combined into one
EngagementResult-shaped object, each finding tagged with the sub-target
that produced it. The parent's role is strictly orchestration -- it
never invents findings.

Sub-runs run in a bounded thread pool (default 2 -- most LLM backends
rate-limit aggressively; concurrency beyond that burns budget on
retries). Failures are contained: a failed sub-run returns an error
result for its group and never takes down the others.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

from tradecraft.coverage.matrix import CoverageMatrix
from tradecraft.execution.loop import EngagementResult, run_engagement
from tradecraft.memory.facts import FactStore

# Groups are keyed by host; each group's sub-run gets the union of that
# host's ports as its scope. Host-level (not port-level) grouping keeps
# sub-run count sane on ports-heavy targets.
DEFAULT_MAX_WORKERS = 2


def plan_fanout(
    facts: FactStore,
    *,
    max_groups: int = 8,
    known_hosts: set[str] | None = None,
) -> List[Dict[str, Any]]:
    """Group host:ports from the FactStore into per-host work units.
    `known_hosts` (hosts covered by a prior run) marks already-scanned
    surface so planning can prefer *new* hosts first -- a re-run of a
    fully-scanned host sorts last, it doesn't vanish (the model may
    still want to re-test).

    Returns [{host, ports, known}] ordered new-surface-first."""
    ports_by_host: Dict[str, list] = {}
    for (host, port), _ in facts.sorted_records():
        ports_by_host.setdefault(host, []).append(port)

    known = known_hosts or set()
    groups = [
        {"host": host, "ports": sorted(ports), "known": host in known}
        for host, ports in ports_by_host.items()
    ]
    groups.sort(key=lambda g: (g["known"], g["host"]))
    return groups[:max_groups]


def plan_fanout_from_matrix(
    matrix: CoverageMatrix,
    *,
    max_groups: int = 8,
) -> List[Dict[str, Any]]:
    """Coverage-driven variant: prioritize hosts with open threads
    (partial cells -- discovered-but-untested), then fully-untested
    hosts, then covered hosts last."""
    priority: Dict[str, int] = {}
    for cell in matrix.open_threads():
        host = cell.target.rsplit(":", 1)[0]
        priority[host] = max(priority.get(host, 0), 2)
    groups = plan_fanout(_matrix_facts(matrix), max_groups=max_groups)
    groups.sort(key=lambda g: (-priority.get(g["host"], 0), g["known"], g["host"]))
    return groups


def _matrix_facts(matrix: CoverageMatrix) -> FactStore:
    """Rebuild a minimal FactStore from matrix rows so the planner can
    consume a matrix directly."""
    store = FactStore()
    for host, port in matrix.rows:
        store.merge_port(host, port, {})
    return store


def run_fanout(
    target: str,
    groups: List[Dict[str, Any]],
    *,
    run_engagement_fn: Callable[..., EngagementResult] = run_engagement,
    max_workers: int = DEFAULT_MAX_WORKERS,
    per_group_kwargs: Dict[str, Any] | None = None,
) -> EngagementResult:
    """Run one focused engagement per group (bounded concurrency), then
    merge deterministically. `run_engagement_fn` is injectable for
    tests and for alternate loop drivers; each sub-run receives:
    target=<host>, tool_ids inherited, seed_context naming its ports."""
    per_group_kwargs = per_group_kwargs or {}

    def one(group: Dict[str, Any]) -> EngagementResult:
        ports = ",".join(str(p) for p in group["ports"])
        seed = (
            f"Focused sub-engagement on {group['host']} (ports: {ports}). "
            "Other hosts are being covered by parallel sub-engagements -- "
            "stay on your assigned target."
        )
        try:
            return run_engagement_fn(
                target=group["host"],
                seed_context=seed,
                **per_group_kwargs,
            )
        except Exception as exc:  # containment: a failed sub-run is a result, not a crash
            return EngagementResult(
                report=f"(sub-engagement on {group['host']} failed: {type(exc).__name__}: {exc})",
                findings=[],
                turns_used=0,
                stats={"fanout_error": str(exc)},
                target=group["host"],
            )

    if not groups:
        return EngagementResult(report="(fanout: no groups to run)", target=target)

    workers = max(1, min(max_workers, len(groups)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        sub_results = list(pool.map(one, groups))

    return _merge(target, groups, sub_results)


def _merge(
    parent_target: str,
    groups: List[Dict[str, Any]],
    sub_results: List[EngagementResult],
) -> EngagementResult:
    """Deterministic merge: combined facts, findings tagged by origin,
    a parent report that lists each sub-run's report verbatim. Stats add
    turns; each sub-run keeps its own run_dir pointer."""
    facts = FactStore()
    findings: List[str] = []
    sections: List[str] = []
    turns = 0
    run_dirs: Dict[str, Any] = {}

    for group, result in zip(groups, sub_results):
        host = group["host"]
        for (r_host, r_port), record in result.facts.sorted_records():
            facts.merge_port(r_host, r_port, dict(record))
        for finding in result.findings:
            findings.append(f"[{host}] {finding}")
        turns += result.turns_used
        if result.run_dir is not None:
            run_dirs[host] = str(result.run_dir)
        sections.append(f"## Sub-engagement: {host}\n\n{result.report}")

    merged_report = "\n\n".join(sections)
    first = sub_results[0]
    return EngagementResult(
        report=merged_report,
        findings=findings,
        turns_used=turns,
        stats={
            "fanout": True,
            "groups": len(groups),
            "failed_groups": sum(1 for r in sub_results if "failed" in r.report[:40].lower()),
        },
        facts=facts,
        evidence=first.evidence,
        run_id=first.run_id,
        run_dir=first.run_dir,
        target=parent_target,
    )
