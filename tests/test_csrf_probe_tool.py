"""Unit tests for the csrf_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.csrf_probe.execute import RawCsrfProbeResult
from tradecraft.tools.csrf_probe import CsrfProbe


def test_tool_attributes():
    tool = CsrfProbe()
    assert tool.tool_id == "csrf_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is True


def test_run_error_is_reported():
    tool = CsrfProbe()
    failed = RawCsrfProbeResult(target="https://example.com", error="invalid 'body' JSON: boom")
    with patch("tradecraft.tools.csrf_probe.csrf_execute.execute", return_value=failed):
        result = tool.run(target="https://example.com", body="bad", token_param="csrf_token")
    assert "error" in result


def test_extract_facts_only_when_vulnerable():
    tool = CsrfProbe()
    params = {"target": "https://example.com/account/email"}
    vulnerable_result = {
        "target": "https://example.com/account/email",
        "vulnerable": True,
        "accepted_variants": ["token_removed"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com"
    assert facts[0]["severity"] == "medium"

    clean_result = {"target": "https://example.com", "vulnerable": False, "accepted_variants": []}
    assert tool.extract_facts(params, clean_result) == []
