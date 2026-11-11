"""Unit tests for the ntlm_info_disclosure_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.ntlm_info_disclosure_probe.execute import RawNtlmResult
from tradecraft.tools.ntlm_info_disclosure_probe import NtlmInfoDisclosureProbe


def test_tool_attributes():
    tool = NtlmInfoDisclosureProbe()
    assert tool.tool_id == "ntlm_info_disclosure_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = NtlmInfoDisclosureProbe()
    failed = RawNtlmResult(target="https://down.example", error="timeout")
    with patch("tradecraft.tools.ntlm_info_disclosure_probe.ntlm_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result["disclosed"] is False
    assert result["error"] == "timeout"


def test_run_disclosed_builds_evidence_and_facts():
    tool = NtlmInfoDisclosureProbe()
    raw = RawNtlmResult(
        target="https://owa.example.com/owa/",
        status_code=401,
        auth_scheme="NTLM",
        ntlm_supported=True,
        challenge_received=True,
        nb_domain_name="EXAMPLE",
        nb_computer_name="DC01",
    )
    with patch("tradecraft.tools.ntlm_info_disclosure_probe.ntlm_execute.execute", return_value=raw):
        result = tool.run(target="https://owa.example.com/owa/")

    assert result["disclosed"] is True
    assert "_full_evidence" in result
    facts = tool.extract_facts({"target": "https://owa.example.com/owa/"}, dict(result))
    assert len(facts) == 1
    assert facts[0]["host"] == "owa.example.com"
    assert facts[0]["port"] == 443
    assert "EXAMPLE" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "medium"

    extracted = tool.extract_evidence({"target": "https://owa.example.com/owa/"}, result)
    assert extracted is not None
    assert extracted[0] == "owa.example.com"


def test_extract_facts_empty_when_not_disclosed():
    tool = NtlmInfoDisclosureProbe()
    params = {"target": "https://example.com/"}
    assert tool.extract_facts(params, {"disclosed": False}) == []
    assert tool.extract_evidence(params, {"disclosed": False}) is None
