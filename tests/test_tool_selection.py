"""
Tests for restricting an engagement to a chosen subset of registered
tools (`--tools` on the CLI, `tool_ids` on run_engagement).

Tests here patch Tool.is_available() to always return True: these are
testing _build_tool_map's own tool_ids/memory-tool-inclusion logic, not
the separate (tested elsewhere, see test_unavailable_tools_are_excluded.py)
is_available()-based exclusion -- without this patch, these tests would
silently depend on exactly which real binaries happen to be on whatever
machine runs pytest, which is not this file's concern.
"""
import pytest

from tradecraft.execution.loop import _build_tool_map
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.registry import ALL_TOOLS


@pytest.fixture(autouse=True)
def _all_tools_available(monkeypatch):
    # Patch each registered tool's own is_available() directly, not just
    # the Tool base class's -- several tools (clairvoyance, linkfinder,
    # tplmap, playwright_engine, spa_crawl, gitdorker, ...) override it
    # themselves with a real file-existence/import/credential check,
    # which would otherwise still run for real here and shadow a
    # base-class-only patch.
    for t in ALL_TOOLS:
        monkeypatch.setattr(type(t), "is_available", lambda self: True)


def test_tool_ids_none_includes_every_registered_tool_plus_memory_tools():
    memory = EngagementMemory()
    # Default: allow_destructive=False excludes destructive tools
    tools = _build_tool_map(memory, tool_ids=None, allow_destructive=False)
    for t in ALL_TOOLS:
        if not t.destructive:
            assert t.spec.name in tools
        else:
            assert t.spec.name not in tools
    assert "log_note" in tools
    assert "log_finding" in tools
    assert "retract_finding" in tools
    assert "recall_memory" in tools
    assert "read_evidence" in tools
    assert "search_evidence" in tools

    # With allow_destructive=True, includes all registered tools
    tools_all = _build_tool_map(memory, tool_ids=None, allow_destructive=True)
    for t in ALL_TOOLS:
        assert t.spec.name in tools_all


def test_tool_ids_restricts_to_chosen_subset():
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["nmap_scan", "subfinder"])
    assert set(tools) == {
        "nmap_scan", "subfinder", "log_note", "log_finding", "retract_finding",
        "recall_memory", "read_evidence", "search_evidence",
    }


def test_memory_tools_are_always_included_even_if_not_requested():
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["nmap_scan"])
    assert "log_note" in tools
    assert "log_finding" in tools
    assert "retract_finding" in tools
    assert "recall_memory" in tools
    assert "read_evidence" in tools
    assert "search_evidence" in tools


def test_unknown_tool_id_raises_value_error():
    memory = EngagementMemory()
    with pytest.raises(ValueError, match="unknown tool"):
        _build_tool_map(memory, tool_ids=["not_a_real_tool"])


def test_dispatch_tool_disabled_policy_error(tmp_path):
    from tradecraft.execution.loop import _dispatch_tool
    from tradecraft.memory.facts import FactStore

    facts = FactStore()
    memory = EngagementMemory()
    # tool_map only has nmap_scan
    tool_map = _build_tool_map(memory, tool_ids=["nmap_scan"])

    # sqlmap is registered in ALL_TOOLS but disabled by operator policy
    res = _dispatch_tool("sqlmap", {"target": "http://10.0.0.1"}, tool_map, facts)
    assert "error" in res
    assert "disabled for this engagement by operator policy" in res["error"]
    assert "available tools:" in res["error"]

    # completely unknown tool returns generic unknown error
    res_unknown = _dispatch_tool("nonexistent_tool_xyz", {"target": "10.0.0.1"}, tool_map, facts)
    assert res_unknown == {"error": "unknown tool 'nonexistent_tool_xyz'"}

