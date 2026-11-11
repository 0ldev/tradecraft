"""Unit tests for the prototype_pollution_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.prototype_pollution_probe.execute import RawPrototypePollutionResult
from tradecraft.tools.prototype_pollution_probe import PrototypePollutionProbe


def test_tool_attributes():
    tool = PrototypePollutionProbe()
    assert tool.tool_id == "prototype_pollution_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = PrototypePollutionProbe()
    failed = RawPrototypePollutionResult(target="https://example.com", error="invalid baseline 'body' JSON: boom")
    with patch("tradecraft.tools.prototype_pollution_probe.ppp_execute.execute", return_value=failed):
        result = tool.run(target="https://example.com", body="bad")
    assert "error" in result


def test_extract_facts_severity_escalates_on_cross_endpoint_leak():
    tool = PrototypePollutionProbe()
    params = {"target": "https://example.com/api/search"}
    cross_endpoint_result = {
        "target": "https://example.com/api/search",
        "vulnerable": True,
        "leaked_cross_endpoint": True,
        "reflected_vectors": [],
    }
    facts = tool.extract_facts(params, dict(cross_endpoint_result))
    assert facts[0]["severity"] == "high"

    direct_only_result = {
        "target": "https://example.com/api/search",
        "vulnerable": True,
        "leaked_cross_endpoint": False,
        "reflected_vectors": ["json___proto__"],
    }
    facts = tool.extract_facts(params, dict(direct_only_result))
    assert facts[0]["severity"] == "medium"

    clean_result = {"target": "https://example.com", "vulnerable": False}
    assert tool.extract_facts(params, clean_result) == []
