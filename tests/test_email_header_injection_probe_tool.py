"""Unit tests for the email_header_injection_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.email_header_injection_probe.execute import RawEmailHeaderInjectionResult
from tradecraft.tools.email_header_injection_probe import EmailHeaderInjectionProbe


def test_tool_attributes():
    tool = EmailHeaderInjectionProbe()
    assert tool.tool_id == "email_header_injection_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is True


def test_run_error_is_reported():
    tool = EmailHeaderInjectionProbe()
    failed = RawEmailHeaderInjectionResult(target="https://example.com/contact", error="field_to_inject is required")
    with patch("tradecraft.tools.email_header_injection_probe.ehi_execute.execute", return_value=failed):
        result = tool.run(target="https://example.com/contact", body="{}", field_to_inject="")
    assert "error" in result


def test_extract_facts_only_when_vulnerable():
    tool = EmailHeaderInjectionProbe()
    params = {"target": "https://example.com/contact"}
    vulnerable_result = {
        "target": "https://example.com/contact",
        "vulnerable": True,
        "accepted_variants": ["crlf_literal"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com"
    assert "crlf_literal" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "medium"

    not_vulnerable_result = {"target": "https://example.com/contact", "vulnerable": False, "accepted_variants": []}
    assert tool.extract_facts(params, not_vulnerable_result) == []
    assert tool.extract_facts(params, {"error": "boom"}) == []
