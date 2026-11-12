"""Integration tests for the v2 loop paths: dynamic tool menu, coverage
matrix + suggestions in the state message, and verify_finding dispatch.

The LLM is mocked at _complete_with_retry level (same pattern as
tests/test_final_review_nudge.py); everything downstream -- schema
selection, dispatch gating, fact merging -- runs for real.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tradecraft.execution.loop import EngagementResult, _dispatch_tool, run_engagement
from tradecraft.execution.tool_menu import ALWAYS_ON_TOOLS
from tradecraft.memory.facts import FactStore


def _response(content="Report", tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(finish_reason="stop", message=message)
    return SimpleNamespace(choices=[choice], usage=None)


def _call(name, args_json="{}", call_id="c1"):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=args_json),
    )


@pytest.fixture(autouse=True)
def force_menu(monkeypatch):
    monkeypatch.setenv("TRADECRAFT_DYNAMIC_MENU", "1")


def test_menu_mode_gates_unactivated_tool_and_load_tool_activates():
    """Turn 1: model calls nmap_scan without loading its schema -> error.
    Turn 2: model calls load_tool -> schema returned and activated.
    Turn 3: model calls nmap_scan again -- gate passes. Turn 4: finalize."""
    class _FakeTool:
        tool_id = "nmap_scan"
        destructive = False
        destructive_categories = frozenset()
        scope_param = "target"

        @property
        def spec(self):
            return SimpleNamespace(
                name="nmap_scan", description="Port scan.",
                parameters={"type": "object", "properties": {}},
            )

        def is_available(self):
            return True

        def run(self, **params):
            return {"result": "scanned"}

        def extract_facts(self, params, result):
            return []

        def extract_evidence(self, params, result):
            return None

        def __call__(self, **params):
            return self.run(**params)

    fake_tool = _FakeTool()

    calls = [
        _response(tool_calls=[_call("nmap_scan", '{"target": "10.0.0.5"}', "c1")]),
        _response(tool_calls=[_call("load_tool", '{"tool_name": "nmap_scan"}', "c2")]),
        _response(tool_calls=[_call("nmap_scan", '{"target": "10.0.0.5"}', "c3")]),
        _response(content="Final report."),
    ]

    with patch("tradecraft.execution.loop._complete_with_retry", side_effect=calls):
        with patch("tradecraft.execution.loop.ALL_TOOLS", [fake_tool]):
            result = run_engagement("example.com", model="test-model", max_turns=6)

    # Turn 1 result: gated with the load_tool instruction.
    turn1 = result.transcript[2]["content"]
    assert "load_tool" in turn1 and "not loaded" in turn1
    # Turn 2 result: schema returned.
    turn2 = result.transcript[4]["content"]
    assert "nmap_scan" in turn2 and "schema" in turn2
    # Turn 3: the real tool ran.
    turn3 = result.transcript[6]["content"]
    assert "scanned" in turn3
    assert result.report == "Final report."


def test_state_message_carries_v2_sections():
    """Coverage matrix, suggestions, and verification sections all appear
    in the state message the loop builds."""
    captured = {}

    def fake_complete(**kwargs):
        captured["messages"] = kwargs["messages"]
        return _response(content="Final report.")

    seeded = FactStore()
    seeded.merge_port("example.com", 80, {"http_title": "Login", "params_discovered": "q"})

    with patch("tradecraft.execution.loop._complete_with_retry", side_effect=fake_complete):
        with patch("tradecraft.execution.loop.FactStore", return_value=seeded):
            run_engagement("example.com", model="test-model", max_turns=1)

    state = captured["messages"][-1]["content"]
    assert "## Coverage Matrix" in state
    assert "example.com:80" in state
    assert "## Suggested Next Actions" in state
    assert "## Finding Verification" in state
    assert "no findings logged yet" in state


def test_small_toolset_sends_all_schemas_without_menu(monkeypatch):
    """Below the menu threshold (and with no env override), every schema
    is sent and no Tool Menu section appears -- the pre-2.0 behavior."""
    monkeypatch.delenv("TRADECRAFT_DYNAMIC_MENU", raising=False)

    captured = {}

    def fake_complete(**kwargs):
        captured["tools"] = kwargs.get("tools")
        captured["messages"] = kwargs.get("messages")
        return _response(content="Final report.")

    with patch("tradecraft.execution.loop._complete_with_retry", side_effect=fake_complete):
        with patch("tradecraft.execution.loop.ALL_TOOLS", []):
            run_engagement("example.com", model="test-model", max_turns=1)

    state = captured["messages"][-1]["content"]
    assert "## Tool Menu" not in state
    # All always-on schemas sent (memory tools are bound instances).
    sent_names = {s["function"]["name"] for s in (captured["tools"] or [])}
    assert "log_note" in sent_names and "verify_finding" in sent_names


def test_dispatch_menu_gate_bypasses_always_on():
    from tradecraft.memory.evidence import EvidenceStore
    from tradecraft.memory.log import EngagementMemory
    from tradecraft.tools.evidence_tools import ReadEvidence

    evidence = EvidenceStore()
    tool_map = {"read_evidence": ReadEvidence(evidence)}
    # read_evidence is always-on: callable even with an empty active set.
    result = _dispatch_tool(
        "read_evidence", {"target": "x", "tool_id": "t"}, tool_map,
        FactStore(), evidence=evidence, menu_active=set(),
    )
    assert "error" not in result or "not loaded" not in str(result.get("error", ""))
