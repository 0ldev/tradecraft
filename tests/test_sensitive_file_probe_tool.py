"""Unit tests for the sensitive_file_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.sensitive_file_probe.execute import RawSensitiveFileResult
from tradecraft.tools.sensitive_file_probe import SensitiveFileProbe


def test_tool_attributes():
    tool = SensitiveFileProbe()
    assert tool.tool_id == "sensitive_file_probe"
    assert tool.spec.name == "sensitive_file_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = SensitiveFileProbe()
    failed = RawSensitiveFileResult(target="https://down.example", error="Connection refused")
    with patch("tradecraft.tools.sensitive_file_probe.sfp_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result == {"target": "https://down.example", "error": "Connection refused"}


def test_run_success_builds_evidence_and_facts():
    tool = SensitiveFileProbe()
    params = {"target": "https://example.com"}
    result = {
        "target": "https://example.com",
        "baseline_status_code": 404,
        "paths_checked": 16,
        "hits_found": 1,
        "hits": [{"path": "/.env", "status_code": 200, "hit": True, "body_snippet": "DB_PASSWORD=x"}],
        "checked": [],
    }
    facts = tool.extract_facts(params, dict(result))
    assert len(facts) == 1
    assert facts[0]["host"] == "example.com"
    assert facts[0]["port"] == 443
    assert "/.env" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "high"


def test_extract_facts_empty_on_no_hits_or_error():
    tool = SensitiveFileProbe()
    params = {"target": "https://example.com"}
    assert tool.extract_facts(params, {"error": "boom"}) == []
    assert tool.extract_facts(params, {"target": "https://example.com", "hits_found": 0, "hits": []}) == []


def test_extract_evidence_pops_full_evidence():
    tool = SensitiveFileProbe()
    params = {"target": "https://example.com"}
    result = {"target": "https://example.com", "_full_evidence": {"raw": "data"}}
    extracted = tool.extract_evidence(params, result)
    assert extracted is not None
    host, full = extracted
    assert host == "example.com"
    assert "_full_evidence" not in result
