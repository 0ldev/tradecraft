"""Unit tests for the mass_assignment_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.mass_assignment_probe.execute import RawMassAssignmentResult
from tradecraft.tools.mass_assignment_probe import MassAssignmentProbe


def test_tool_attributes():
    tool = MassAssignmentProbe()
    assert tool.tool_id == "mass_assignment_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is True


def test_run_error_is_reported():
    tool = MassAssignmentProbe()
    failed = RawMassAssignmentResult(target="https://api.example.com", error="invalid baseline 'body' JSON: boom")
    with patch("tradecraft.tools.mass_assignment_probe.map_execute.execute", return_value=failed):
        result = tool.run(target="https://api.example.com", body="bad")
    assert "error" in result


def test_extract_facts_only_on_confirmed_accept():
    tool = MassAssignmentProbe()
    params = {"target": "https://api.example.com/users/1"}
    confirmed_result = {
        "target": "https://api.example.com/users/1",
        "confirmed_accepted": 1,
        "attempts": [{"field": "isAdmin", "classification": "accepted_confirmed"}],
    }
    facts = tool.extract_facts(params, dict(confirmed_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "api.example.com"
    assert "isAdmin" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "high"

    unconfirmed_result = {"target": "https://api.example.com/users/1", "confirmed_accepted": 0, "attempts": []}
    assert tool.extract_facts(params, unconfirmed_result) == []
    assert tool.extract_facts(params, {"error": "boom"}) == []
