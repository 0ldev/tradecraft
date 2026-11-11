"""Unit tests for the workflow_step_bypass_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.workflow_step_bypass_probe.execute import RawWorkflowStepResult
from tradecraft.tools.workflow_step_bypass_probe import WorkflowStepBypassProbe


def test_tool_attributes():
    tool = WorkflowStepBypassProbe()
    assert tool.tool_id == "workflow_step_bypass_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is True


def test_run_error_is_reported():
    tool = WorkflowStepBypassProbe()
    failed = RawWorkflowStepResult(target="https://down.example", error="boom")
    with patch("tradecraft.tools.workflow_step_bypass_probe.workflow_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result == {"target": "https://down.example", "method": "POST", "error": "boom"}


def test_confirmed_bypass_builds_evidence_and_facts():
    tool = WorkflowStepBypassProbe()
    raw = RawWorkflowStepResult(
        target="https://shop.example.com/api/checkout/42/confirm",
        method="POST",
        status_code=200,
        body='{"status":"paid"}',
        classification="accepted_confirmed",
        marker_found=True,
        success_marker='"status":"paid"',
    )
    with patch("tradecraft.tools.workflow_step_bypass_probe.workflow_execute.execute", return_value=raw):
        result = tool.run(target="https://shop.example.com/api/checkout/42/confirm")

    assert result["step_bypass_suspected"] is True
    assert "_full_evidence" in result
    facts = tool.extract_facts({"target": "https://shop.example.com/api/checkout/42/confirm"}, dict(result))
    assert len(facts) == 1
    assert facts[0]["host"] == "shop.example.com"
    assert facts[0]["port"] == 443
    assert facts[0]["severity"] == "high"

    extracted = tool.extract_evidence({"target": "https://shop.example.com/api/checkout/42/confirm"}, result)
    assert extracted is not None
    assert extracted[0] == "shop.example.com"


def test_unconfirmed_is_evidence_but_not_a_fact():
    tool = WorkflowStepBypassProbe()
    result = {
        "target": "https://shop.example.com/api/checkout/42/confirm",
        "classification": "accepted_unconfirmed",
        "step_bypass_suspected": True,
    }
    assert tool.extract_facts({"target": result["target"]}, dict(result)) == []
    assert tool.extract_evidence({"target": result["target"]}, dict(result)) is None


def test_blocked_is_not_a_fact_or_evidence():
    tool = WorkflowStepBypassProbe()
    result = {
        "target": "https://shop.example.com/api/checkout/42/confirm",
        "classification": "blocked",
        "step_bypass_suspected": False,
    }
    assert tool.extract_facts({"target": result["target"]}, dict(result)) == []
    assert tool.extract_evidence({"target": result["target"]}, dict(result)) is None
