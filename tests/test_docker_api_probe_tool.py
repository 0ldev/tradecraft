"""
Unit tests for the docker_api_probe tool layer.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.docker_api_probe.execute import RawDockerApiResult
from tradecraft.tools.docker_api_probe import DockerApiProbe


def test_run_reachable():
    tool = DockerApiProbe()
    raw = RawDockerApiResult(
        target="192.168.1.50", host="192.168.1.50", port=2375, reachable=True,
        version_info={"Version": "24.0.5"}, info={"Containers": 1},
        containers=[{"Names": ["/app"]}],
    )
    with patch("tradecraft.tools.docker_api_probe.docker_execute", return_value=raw):
        result = tool.run(target="192.168.1.50")

    assert result["reachable"] is True
    assert result["docker_version"] == "24.0.5"
    assert "_full_evidence" in result


def test_extract_facts_reachable():
    tool = DockerApiProbe()
    params = {"target": "192.168.1.50"}
    result = {
        "reachable": True, "host": "192.168.1.50", "port": 2375,
        "docker_version": "24.0.5", "evidence_id": "docker_api_probe:192.168.1.50",
    }
    facts = tool.extract_facts(params, result)
    assert len(facts) == 1
    assert facts[0]["severity"] == "critical"
    assert facts[0]["service"] == "docker-api"
    assert facts[0]["version"] == "24.0.5"


def test_extract_facts_not_reachable():
    tool = DockerApiProbe()
    assert tool.extract_facts({"target": "192.168.1.50"}, {"reachable": False}) == []


def test_extract_evidence_pops_full_evidence():
    tool = DockerApiProbe()
    params = {"target": "192.168.1.50"}
    result = {"host": "192.168.1.50", "_full_evidence": {"target": "192.168.1.50"}}
    evidence = tool.extract_evidence(params, result)
    assert evidence is not None
    host, full = evidence
    assert host == "192.168.1.50"
    assert "_full_evidence" not in result


def test_extract_evidence_none_without_full_evidence():
    tool = DockerApiProbe()
    assert tool.extract_evidence({"target": "192.168.1.50"}, {"host": "192.168.1.50"}) is None
