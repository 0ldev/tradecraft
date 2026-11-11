"""
Unit tests for the jenkins_unauth_probe tool layer.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.jenkins_unauth_probe.execute import RawJenkinsProbeResult
from tradecraft.tools.jenkins_unauth_probe import JenkinsUnauthProbe


def test_run_positive():
    tool = JenkinsUnauthProbe()
    raw = RawJenkinsProbeResult(
        target="ci.example.com", base_url="https://ci.example.com", is_jenkins=True,
        jenkins_version="2.401.3", script_console_reachable=True, manage_reachable=True,
        api_json={"mode": "NORMAL", "jobs": [{"name": "j1"}]},
    )
    with patch("tradecraft.tools.jenkins_unauth_probe.jenkins_execute", return_value=raw):
        result = tool.run(target="ci.example.com")

    assert result["is_jenkins"] is True
    assert result["jenkins_version"] == "2.401.3"
    assert "_full_evidence" in result


def test_extract_facts_script_console_critical():
    tool = JenkinsUnauthProbe()
    params = {"target": "ci.example.com"}
    result = {
        "is_jenkins": True, "jenkins_version": "2.401.3", "script_console_reachable": True,
        "manage_panel_reachable": True, "evidence_id": "jenkins_unauth_probe:ci.example.com",
    }
    facts = tool.extract_facts(params, result)
    assert len(facts) == 1
    assert facts[0]["severity"] == "critical"
    assert "RCE-capable" in facts[0]["vulnerability"]


def test_extract_facts_manage_only_high():
    tool = JenkinsUnauthProbe()
    params = {"target": "ci.example.com"}
    result = {"is_jenkins": True, "script_console_reachable": False, "manage_panel_reachable": True}
    facts = tool.extract_facts(params, result)
    assert len(facts) == 1
    assert facts[0]["severity"] == "high"


def test_extract_facts_not_jenkins():
    tool = JenkinsUnauthProbe()
    assert tool.extract_facts({"target": "example.com"}, {"is_jenkins": False}) == []


def test_extract_evidence_pops_full_evidence():
    tool = JenkinsUnauthProbe()
    params = {"target": "ci.example.com"}
    result = {"is_jenkins": True, "_full_evidence": {"target": "ci.example.com"}}
    evidence = tool.extract_evidence(params, result)
    assert evidence is not None
    host, full = evidence
    assert host == "ci.example.com"
    assert "_full_evidence" not in result


def test_extract_evidence_none_without_full_evidence():
    tool = JenkinsUnauthProbe()
    assert tool.extract_evidence({"target": "ci.example.com"}, {"is_jenkins": False}) is None
