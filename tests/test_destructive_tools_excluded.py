"""
Regression test for the destructive-tool gating in _build_tool_map
and _dispatch_tool (tradecraft/execution/loop.py): a tool whose own
contract declares destructive: true must not appear in the tool map
by default, so its schema is never rendered to the model and it's
never offered as something the model could call unless the operator
explicitly passed allow_destructive=True.
"""
from __future__ import annotations

from typing import Any, Dict

import pytest
from tradecraft.domain import ToolSpec
from tradecraft.execution.loop import _build_tool_map, _dispatch_tool
from tradecraft.memory.facts import FactStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.policy.destructive import is_allowed
from tradecraft.tools.base import Tool
from tradecraft.tools.nmap_scan import NmapScan
from tradecraft.tools.registry import ALL_TOOLS


class DummyDestructiveTool(Tool):
    tool_id = "dummy_destructive"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="dummy_destructive",
            description="A dummy destructive tool for testing",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host"},
                },
            },
        )

    @property
    def required_binary(self) -> str | None:
        return None

    @property
    def scope_param(self) -> str | None:
        return "target"

    def is_available(self) -> bool:
        return True

    @property
    def destructive(self) -> bool:
        return True

    @property
    def destructive_categories(self) -> frozenset[str]:
        return frozenset({"state_mutation"})

    def run(self, target: str = "") -> Dict[str, Any]:
        return {"result": f"mutated {target}"}


@pytest.fixture
def dummy_tool(monkeypatch):
    dummy = DummyDestructiveTool()
    monkeypatch.setattr("tradecraft.tools.registry.ALL_TOOLS", [*ALL_TOOLS, dummy])
    monkeypatch.setattr("tradecraft.execution.loop.ALL_TOOLS", [*ALL_TOOLS, dummy])
    return dummy


def test_destructive_policy_is_allowed():
    empty: frozenset[str] = frozenset()
    one = frozenset({"state_mutation"})
    two = frozenset({"state_mutation", "code_execution"})

    # Non-destructive (no categories) is always allowed.
    assert is_allowed(empty, allow_destructive=False) is True
    assert is_allowed(empty, allow_destructive=True) is True

    # --allow-destructive allows everything regardless of category.
    assert is_allowed(one, allow_destructive=True) is True
    assert is_allowed(two, allow_destructive=True) is True

    # Neither flag set: destructive tool is blocked.
    assert is_allowed(one, allow_destructive=False) is False

    # Finer-grained opt-in: allowed only if ALL categories are covered.
    assert is_allowed(one, allow_destructive=False, allowed_categories=frozenset({"state_mutation"})) is True
    assert is_allowed(two, allow_destructive=False, allowed_categories=frozenset({"state_mutation"})) is False
    assert is_allowed(
        two, allow_destructive=False, allowed_categories=frozenset({"state_mutation", "code_execution"})
    ) is True


def test_destructive_tool_excluded_by_default(dummy_tool):
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["dummy_destructive"])
    assert "dummy_destructive" not in tools
    # Memory and evidence tools remain present
    assert "log_note" in tools
    assert "log_finding" in tools
    assert "retract_finding" in tools
    assert "read_evidence" in tools
    assert "search_evidence" in tools


def test_destructive_tool_included_with_allow_destructive(dummy_tool):
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["dummy_destructive"], allow_destructive=True)
    assert "dummy_destructive" in tools


def test_destructive_exclusion_reported_to_stdout(dummy_tool, capsys):
    memory = EngagementMemory()
    _build_tool_map(memory, tool_ids=["dummy_destructive"])
    out = capsys.readouterr().out
    assert "excluded 1 destructive tool(s)" in out
    assert "--allow-destructive/--allow-destructive-categories insufficient" in out
    assert "dummy_destructive" in out


def test_no_exclusion_stdout_when_allowed_or_clean(dummy_tool, monkeypatch, capsys):
    monkeypatch.setattr(NmapScan, "is_available", lambda self: True)
    memory = EngagementMemory()
    _build_tool_map(memory, tool_ids=["dummy_destructive", "nmap_scan"], allow_destructive=True)
    out = capsys.readouterr().out
    assert "excluded" not in out


def test_dispatch_destructive_tool_reports_specific_error(dummy_tool):
    memory = EngagementMemory()
    tool_map = _build_tool_map(memory, tool_ids=["dummy_destructive"], allow_destructive=False)
    assert "dummy_destructive" not in tool_map

    facts = FactStore()
    result = _dispatch_tool("dummy_destructive", {"target": "example.com"}, tool_map, facts)
    assert "error" in result
    assert "tool 'dummy_destructive' is destructive and --allow-destructive was not set" in result["error"]
    assert "available tools:" in result["error"]


def test_dispatch_operator_disabled_tool_reports_generic_error():
    memory = EngagementMemory()
    # Explicit tool subset excluding nmap_scan
    tool_map = _build_tool_map(memory, tool_ids=["subfinder"])
    assert "nmap_scan" not in tool_map

    facts = FactStore()
    result = _dispatch_tool("nmap_scan", {"target": "example.com"}, tool_map, facts)
    assert "error" in result
    assert "tool 'nmap_scan' is disabled for this engagement by operator policy" in result["error"]
