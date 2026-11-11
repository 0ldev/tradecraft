"""Unit tests for the host_header_injection_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.host_header_injection_probe.execute import RawHostHeaderResult
from tradecraft.tools.host_header_injection_probe import HostHeaderInjectionProbe


def test_tool_attributes():
    tool = HostHeaderInjectionProbe()
    assert tool.tool_id == "host_header_injection_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = HostHeaderInjectionProbe()
    failed = RawHostHeaderResult(target="https://down.example", error="Connection refused")
    with patch("tradecraft.tools.host_header_injection_probe.hhi_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result == {"target": "https://down.example", "error": "Connection refused"}


def test_extract_facts_only_when_vulnerable():
    tool = HostHeaderInjectionProbe()
    params = {"target": "https://example.com/forgot-password"}
    vulnerable_result = {
        "target": "https://example.com/forgot-password",
        "vulnerable": True,
        "reflected_headers": ["X-Forwarded-Host"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com"
    assert "X-Forwarded-Host" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "high"

    clean_result = {"target": "https://example.com", "vulnerable": False, "reflected_headers": []}
    assert tool.extract_facts(params, clean_result) == []
