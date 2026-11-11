"""
Unit tests for the path_traversal_probe tool layer.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.path_traversal_probe import parse as trav_parse
from tradecraft.tools.path_traversal_probe import PathTraversalProbe


def test_run_confirmed_vulnerable():
    tool = PathTraversalProbe()
    payloads = trav_parse.build_traversal_payloads()
    mock_raw = trav_parse.RawTraversalResult(
        target="https://target.com/download",
        parameter="file",
        tested_count=1,
        probes=[
            trav_parse.RawTraversalProbe(
                payload=payloads[0][0],
                file_description=payloads[0][1],
                status_code=200,
                url="https://target.com/download?file=../../../../../../../etc/passwd",
                body="root:x:0:0:root:/root:/bin/bash\n",
                confirmed=True,
            )
        ],
        followup_probes=[
            trav_parse.RawTraversalProbe(
                payload="../../../../../../../proc/self/environ",
                file_description="Process environment variables (proc/self/environ)",
                status_code=200,
                url="https://target.com/download?file=../../../../../../../proc/self/environ",
                body="PATH=/usr/bin\x00DB_PASSWORD=s3cr3t\x00",
                confirmed=True,
            ),
            trav_parse.RawTraversalProbe(
                payload="../../../../../../../etc/shadow",
                file_description="/etc/shadow (root password hashes)",
                status_code=403,
                url="https://target.com/download?file=../../../../../../../etc/shadow",
                body="Forbidden",
                confirmed=False,
            ),
        ],
    )
    with patch("tradecraft.tools.path_traversal_probe.trav_execute", return_value=mock_raw):
        result = tool.run(target="https://target.com/download", parameter="file")

    assert result["vulnerable"] is True
    assert result["confirmed_payload"] == payloads[0][0]
    assert result["confirmed_file"] == payloads[0][1]
    assert result["harvested_files"] == ["Process environment variables (proc/self/environ)"]
    assert result["harvested_count"] == 1
    assert "_full_evidence" in result
    assert len(result["_full_evidence"]["followup_probes"]) == 2


def test_run_not_vulnerable():
    tool = PathTraversalProbe()
    mock_raw = trav_parse.RawTraversalResult(
        target="https://target.com/download",
        parameter="file",
        tested_count=1,
        probes=[
            trav_parse.RawTraversalProbe(
                payload="../../../../../../../etc/passwd",
                file_description="/etc/passwd (raw traversal)",
                status_code=200,
                url="https://target.com/download",
                body="clean page",
            )
        ],
    )
    with patch("tradecraft.tools.path_traversal_probe.trav_execute", return_value=mock_raw):
        result = tool.run(target="https://target.com/download", parameter="file")

    assert result["vulnerable"] is False
    assert "confirmed_payload" not in result


def test_extract_facts_vulnerable():
    tool = PathTraversalProbe()
    params = {"target": "https://target.com/download", "parameter": "file"}
    result = {
        "vulnerable": True,
        "confirmed_file": "/etc/passwd (raw traversal)",
        "evidence_id": "path_traversal_probe:target.com/download",
    }
    facts = tool.extract_facts(params, result)
    assert len(facts) == 1
    assert facts[0]["severity"] == "high"
    assert "file" in facts[0]["vulnerability"]
    assert facts[0]["evidence"] == "path_traversal_probe:target.com/download"


def test_extract_facts_harvested_files_escalates_to_critical():
    tool = PathTraversalProbe()
    params = {"target": "https://target.com/download", "parameter": "file"}
    result = {
        "vulnerable": True,
        "confirmed_file": "/etc/passwd (raw traversal)",
        "harvested_count": 2,
    }
    facts = tool.extract_facts(params, result)
    assert facts[0]["severity"] == "critical"
    assert facts[0]["harvested_files_count"] == 2


def test_extract_facts_not_vulnerable():
    tool = PathTraversalProbe()
    params = {"target": "https://target.com/download", "parameter": "file"}
    result = {"vulnerable": False}
    assert tool.extract_facts(params, result) == []


def test_extract_evidence_pops_full_evidence():
    tool = PathTraversalProbe()
    params = {"target": "https://target.com/download"}
    result = {"vulnerable": False, "_full_evidence": {"target": "https://target.com/download", "probes": []}}
    evidence = tool.extract_evidence(params, result)
    assert evidence is not None
    host, full = evidence
    assert host == "target.com/download"
    assert full["probes"] == []
    assert "_full_evidence" not in result


def test_extract_evidence_none_without_full_evidence():
    tool = PathTraversalProbe()
    params = {"target": "https://target.com/download"}
    result = {"vulnerable": False}
    assert tool.extract_evidence(params, result) is None
