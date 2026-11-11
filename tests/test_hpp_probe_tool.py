"""Unit tests for the hpp_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.hpp_probe.execute import RawHppAttempt, RawHppResult
from tradecraft.tools.hpp_probe import HppProbe


def test_tool_attributes():
    tool = HppProbe()
    assert tool.tool_id == "hpp_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = HppProbe()
    failed = RawHppResult(target="https://down.example", error="boom")
    with patch("tradecraft.tools.hpp_probe.hpp_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result == {"target": "https://down.example", "method": "GET", "error": "boom"}


def test_run_observed_builds_evidence_but_no_facts():
    tool = HppProbe()
    raw = RawHppResult(
        target="https://example.com/search?q=test",
        method="GET",
        param_names=["q"],
        baseline_status=200,
        baseline_length=2,
        attempts=[
            RawHppAttempt(
                param="q",
                location="query",
                ordering="original_then_sentinel",
                url="https://example.com/search?q=test&q=rs_hpp_deadbeef",
                sentinel="rs_hpp_deadbeef",
                status_code=200,
                body_length=25,
                sentinel_reflected=True,
                response_changed=True,
            )
        ],
    )
    with patch("tradecraft.tools.hpp_probe.hpp_execute.execute", return_value=raw):
        result = tool.run(target="https://example.com/search?q=test")

    assert result["hpp_observed"] is True
    assert "_full_evidence" in result
    assert tool.extract_facts({"target": "https://example.com/search?q=test"}, dict(result)) == []

    extracted = tool.extract_evidence({"target": "https://example.com/search?q=test"}, result)
    assert extracted is not None
    assert extracted[0] == "example.com"


def test_no_evidence_when_nothing_observed():
    tool = HppProbe()
    params = {"target": "https://example.com/search?q=test"}
    assert tool.extract_evidence(params, {"hpp_observed": False}) is None
