"""Unit tests for the saml_signature_bypass_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.saml_signature_bypass_probe.execute import RawSamlBypassResult
from tradecraft.tools.saml_signature_bypass_probe import SamlSignatureBypassProbe


def test_tool_attributes():
    tool = SamlSignatureBypassProbe()
    assert tool.tool_id == "saml_signature_bypass_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = SamlSignatureBypassProbe()
    failed = RawSamlBypassResult(target="https://app.example.com/saml/acs", error="'saml_response' is not valid base64: boom")
    with patch("tradecraft.tools.saml_signature_bypass_probe.ssbp_execute.execute", return_value=failed):
        result = tool.run(target="https://app.example.com/saml/acs", saml_response="bad")
    assert "error" in result


def test_extract_facts_critical_severity_when_vulnerable():
    tool = SamlSignatureBypassProbe()
    params = {"target": "https://app.example.com/saml/acs"}
    vulnerable_result = {
        "target": "https://app.example.com/saml/acs",
        "vulnerable": True,
        "accepted_mutations": ["strip_signature"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "app.example.com"
    assert facts[0]["severity"] == "critical"

    clean_result = {"target": "https://app.example.com/saml/acs", "vulnerable": False, "accepted_mutations": []}
    assert tool.extract_facts(params, clean_result) == []
