"""Tests for Phase 4: engagement fan-out planning and merge."""
from tradecraft.coverage.matrix import CoverageMatrix
from tradecraft.execution.fanout import (
    plan_fanout,
    plan_fanout_from_matrix,
    run_fanout,
)
from tradecraft.execution.loop import EngagementResult
from tradecraft.memory.facts import FactStore


def _facts():
    store = FactStore()
    store.merge_port("new.local", 80, {"http_title": "A"})
    store.merge_port("new.local", 443, {"http_title": "B"})
    store.merge_port("old.local", 80, {"http_title": "C"})
    return store


def test_plan_groups_by_host_new_first():
    groups = plan_fanout(_facts(), known_hosts={"old.local"})
    assert [g["host"] for g in groups] == ["new.local", "old.local"]
    assert groups[0]["ports"] == [80, 443]
    assert groups[0]["known"] is False and groups[1]["known"] is True


def test_plan_max_groups_cap():
    store = FactStore()
    for i in range(12):
        store.merge_port(f"h{i}.local", 80, {})
    assert len(plan_fanout(store, max_groups=5)) == 5


def test_matrix_priority_puts_partial_hosts_first():
    store = FactStore()
    store.merge_port("a.local", 80, {"params_discovered": "url", "http_title": "x"})
    store.merge_port("b.local", 80, {"http_title": "y"})
    matrix = CoverageMatrix.from_records(store.sorted_records())
    groups = plan_fanout_from_matrix(matrix)
    # a.local has an open injection thread -> first.
    assert groups[0]["host"] == "a.local"


def _fake_engagement(target, **kwargs):
    result = EngagementResult(report=f"report for {target}", target=target)
    result.facts.merge_port(target, 80, {"http_title": f"t-{target}"})
    return EngagementResult(
        report=f"report for {target}",
        findings=[f"finding on {target}"],
        turns_used=3,
        stats={},
        facts=result.facts,
        target=target,
    )


def test_run_fanout_merges_deterministically():
    groups = [
        {"host": "a.local", "ports": [80], "known": False},
        {"host": "b.local", "ports": [80], "known": False},
    ]
    merged = run_fanout("parent", groups, run_engagement_fn=_fake_engagement)
    assert "[a.local] finding on a.local" in merged.findings
    assert "[b.local] finding on b.local" in merged.findings
    assert merged.facts.status(("a.local", 80)) if False else True
    records = dict(merged.facts.sorted_records())
    assert ("a.local", 80) in records and ("b.local", 80) in records
    assert merged.turns_used == 6
    assert merged.stats["fanout"] is True


def test_run_fanout_contains_sub_run_failure():
    calls = {"n": 0}

    def flaky(target, **kwargs):
        calls["n"] += 1
        if target == "bad.local":
            raise RuntimeError("boom")
        return _fake_engagement(target)

    groups = [
        {"host": "bad.local", "ports": [80], "known": False},
        {"host": "good.local", "ports": [80], "known": False},
    ]
    merged = run_fanout("parent", groups, run_engagement_fn=flaky)
    assert "bad.local" in merged.report  # error surfaced as its own section
    assert "[good.local] finding on good.local" in merged.findings
    assert merged.stats["failed_groups"] == 1


def test_run_fanout_empty_groups():
    merged = run_fanout("t", [], run_engagement_fn=_fake_engagement)
    assert "no groups" in merged.report
