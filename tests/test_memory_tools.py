from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.memory_tools import LogFinding, LogNote, RetractFinding


def test_log_finding_returns_finding_id():
    memory = EngagementMemory()
    tool = LogFinding(memory)
    result = tool.run(text="port 80 open, nginx 1.24.0")
    assert result == {"logged": True, "finding_id": 1}
    assert memory.findings() == ["port 80 open, nginx 1.24.0 [unverified: no evidence_id]"]


def test_log_finding_records_evidence_id_as_source():
    memory = EngagementMemory()
    tool = LogFinding(memory)
    result = tool.run(text="HSTS missing", evidence_id="security_header_check:example.com")
    assert result == {"logged": True, "finding_id": 1}
    assert memory.findings() == ["HSTS missing [evidence: security_header_check:example.com]"]
    assert "FINDING #1 [evidence: security_header_check:example.com]: HSTS missing" in memory.render()


def test_log_finding_blank_evidence_id_counts_as_unverified():
    memory = EngagementMemory()
    LogFinding(memory).run(text="claim", evidence_id="")
    assert memory.findings() == ["claim [unverified: no evidence_id]"]


def test_retracted_finding_still_excluded_with_source_tag():
    memory = EngagementMemory()
    fid = LogFinding(memory).run(text="x", evidence_id="t:h")["finding_id"]
    memory.retract(fid, "wrong")
    assert memory.findings() == []


def test_log_note_unaffected_by_finding_id_change():
    memory = EngagementMemory()
    tool = LogNote(memory)
    assert tool.run(text="just thinking out loud") == {"logged": True}


def test_retract_finding_tool_removes_finding_from_report_list():
    memory = EngagementMemory()
    finding_id = LogFinding(memory).run(text="a finding that turns out to be wrong")["finding_id"]
    result = RetractFinding(memory).run(finding_id=finding_id, reason="contradicted by a later check")
    assert result == {"retracted": True, "finding_id": finding_id}
    assert memory.findings() == []


def test_retract_finding_tool_reports_error_on_unknown_id():
    memory = EngagementMemory()
    result = RetractFinding(memory).run(finding_id=42, reason="never existed")
    assert result["retracted"] is False
    assert "42" in result["error"]


def test_log_finding_verifies_evidence_id_against_evidence_store(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    store.save("example.com", "nuclei", {"findings": [{"id": "cve-2024-1234"}]})
    memory = EngagementMemory()
    tool = LogFinding(memory, evidence=store)

    # Valid evidence_id present in EvidenceStore
    ok_res = tool.run(text="CVE-2024-1234 confirmed", evidence_id="nuclei:example.com")
    assert ok_res == {"logged": True, "finding_id": 1}
    assert memory.findings()[0] == "CVE-2024-1234 confirmed [evidence: nuclei:example.com]"

    # Hallucinated / non-existent evidence_id not in EvidenceStore
    bad_res = tool.run(text="SQLi on /login", evidence_id="sqlmap:example.com")
    assert bad_res["logged"] is True
    assert bad_res["finding_id"] == 2
    assert bad_res["verified_evidence"] is False
    assert "not found in EvidenceStore" in bad_res["warning"]
    assert memory.findings()[1] == "SQLi on /login [unverified: unknown evidence_id sqlmap:example.com]"
    assert "FINDING #2 [unverified: unknown evidence_id sqlmap:example.com]: SQLi on /login" in memory.render()

