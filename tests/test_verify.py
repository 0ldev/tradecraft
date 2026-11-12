"""Tests for Phase 2: deterministic finding verification."""
import tempfile
from pathlib import Path

from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.policy.verify import (
    MISSING_EVIDENCE,
    UNVERIFIED,
    VERIFIED,
    VerifyFinding,
    classify_findings,
    render_verification_summary,
)


def _stores(tmp: Path):
    memory = EngagementMemory()
    evidence = EvidenceStore(persist_dir=str(tmp / "evidence"))
    return memory, evidence


def test_verified_when_evidence_resolves(tmp_path):
    memory, evidence = _stores(tmp_path)
    eid = evidence.save("10.0.0.5", "nmap_scan", {"ports": [80]})
    fid = memory.finding("port 80 open", evidence_id=eid)
    classified = classify_findings(memory, evidence)
    assert classified[0]["status"] == VERIFIED
    assert classified[0]["finding_id"] == fid


def test_unverified_without_evidence_id(tmp_path):
    memory, evidence = _stores(tmp_path)
    memory.finding("looks like an admin panel")
    assert classify_findings(memory, evidence)[0]["status"] == UNVERIFIED


def test_missing_evidence_when_id_doesnt_resolve(tmp_path):
    memory, evidence = _stores(tmp_path)
    memory.finding("claim", evidence_id="nmap_scan:10.9.9.9")
    assert classify_findings(memory, evidence)[0]["status"] == MISSING_EVIDENCE


def test_retracted_findings_excluded(tmp_path):
    memory, evidence = _stores(tmp_path)
    fid = memory.finding("claim")
    memory.retract(fid, "wrong")
    assert classify_findings(memory, evidence) == []


def test_summary_render_statuses(tmp_path):
    memory, evidence = _stores(tmp_path)
    eid = evidence.save("10.0.0.5", "nmap_scan", {"ports": [80]})
    memory.finding("verified claim", evidence_id=eid)
    memory.finding("no evidence")
    text = render_verification_summary(classify_findings(memory, evidence))
    assert "VERIFIED" in text and "UNVERIFIED" in text


def test_verify_finding_tool_happy_path(tmp_path):
    memory, evidence = _stores(tmp_path)
    eid = evidence.save("10.0.0.5", "nmap_scan", {"ports": [80]})
    fid = memory.finding("port 80 open", evidence_id=eid)
    tool = VerifyFinding(memory, evidence)
    result = tool.run(finding_id=fid)
    assert result["status"] == VERIFIED
    assert "ports" in result["evidence_digest"]


def test_verify_finding_tool_missing_id(tmp_path):
    memory, evidence = _stores(tmp_path)
    tool = VerifyFinding(memory, evidence)
    assert "error" in tool.run(finding_id=99)


def test_verify_finding_tool_no_evidence_gives_guidance(tmp_path):
    memory, evidence = _stores(tmp_path)
    fid = memory.finding("claim without evidence")
    tool = VerifyFinding(memory, evidence)
    result = tool.run(finding_id=fid)
    assert result["status"] == UNVERIFIED
    assert "log_finding" in result["note"] or "retract_finding" in result["note"]


def test_verify_finding_tool_retracted(tmp_path):
    memory, evidence = _stores(tmp_path)
    fid = memory.finding("claim")
    memory.retract(fid, "wrong")
    tool = VerifyFinding(memory, evidence)
    result = tool.run(finding_id=fid)
    assert "error" in result and "retracted" in result["error"]


def test_digest_truncates(tmp_path):
    from tradecraft.policy.verify import _digest
    text = _digest({"blob": "x" * 5000}, limit=100)
    assert text.endswith("chars; full evidence on disk)") or "truncated at 100" in text
