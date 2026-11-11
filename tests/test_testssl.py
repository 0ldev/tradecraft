import subprocess
from unittest.mock import patch

from tradecraft.adapters.testssl import execute as testssl_execute
from tradecraft.adapters.testssl import parse as testssl_parse
from tradecraft.tools.testssl import TestSsl

_CSV = (
    '"id","fqdn/ip","port","severity","finding","cve","cwe"\n'
    '"cipher_rc4","10.0.0.5","443","HIGH","RC4 ciphers offered","CVE-2013-2566","CWE-310"\n'
    '"heartbleed","10.0.0.5","443","OK","not vulnerable","",""\n'
    '"service","10.0.0.5","443","INFO","HTTP","",""\n'
)


def _write_csv_and_succeed(argv, **kwargs):
    out_path = argv[argv.index("--csvfile") + 1]
    with open(out_path, "w") as f:
        f.write(_CSV)
    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def test_parse_findings_keeps_only_flagged_rows():
    findings = testssl_parse.parse_findings(_CSV)
    assert findings == [{"id": "cipher_rc4", "severity": "HIGH", "detail": "RC4 ciphers offered"}]


def test_parse_findings_empty_for_blank_csv():
    assert testssl_parse.parse_findings("") == []


def test_parse_all_rows_includes_ok_and_filtered_rows():
    # Unlike parse_findings, parse_all_rows keeps the OK-severity heartbleed
    # row and the INFO-severity service row -- this is what read_evidence
    # must return so hydrating a sparse/empty findings summary actually
    # surfaces new information instead of the same empty list again.
    rows = testssl_parse.parse_all_rows(_CSV)
    ids = [r["id"] for r in rows]
    assert "cipher_rc4" in ids
    assert "heartbleed" in ids
    assert "service" in ids
    assert len(rows) == 3


def test_parse_all_rows_empty_for_blank_csv():
    assert testssl_parse.parse_all_rows("") == []


def test_worst_severity_picks_highest_ranked():
    findings = [{"severity": "LOW"}, {"severity": "HIGH"}, {"severity": "WARN"}]
    assert testssl_parse.worst_severity(findings) == "HIGH"


def test_worst_severity_none_for_no_findings():
    assert testssl_parse.worst_severity([]) is None


def test_host_port_from_target_defaults_to_443():
    assert testssl_parse.host_port_from_target("10.0.0.5") == ("10.0.0.5", 443)
    assert testssl_parse.host_port_from_target("10.0.0.5:8443") == ("10.0.0.5", 8443)


def test_execution_builds_csv_output_file():
    with patch("subprocess.run", side_effect=_write_csv_and_succeed):
        result = testssl_execute.execute("10.0.0.5", timeout=30)
    assert "cipher_rc4" in result.csv_output


def test_returncode_2_is_not_treated_as_an_error():
    def _partial_failure(argv, **kwargs):
        out_path = argv[argv.index("--csvfile") + 1]
        with open(out_path, "w") as f:
            f.write(_CSV)
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="")

    with patch("subprocess.run", side_effect=_partial_failure):
        result = testssl_execute.execute("10.0.0.5", timeout=30)
    assert result.error is None
    assert "cipher_rc4" in result.csv_output


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert testssl_execute.execute("10.0.0.5").error == "testssl executable not found"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("testssl", 90)):
        assert testssl_execute.execute("10.0.0.5").error == "testssl timed out after 90s"


def test_run_returns_parsed_findings():
    with patch("subprocess.run", side_effect=_write_csv_and_succeed):
        result = TestSsl().run(target="10.0.0.5")
    assert result["findings"] == [{"id": "cipher_rc4", "severity": "HIGH", "detail": "RC4 ciphers offered"}]


_CLEAN_CSV = (
    '"id","fqdn/ip","port","severity","finding","cve","cwe"\n'
    '"heartbleed","10.0.0.5","443","OK","not vulnerable","",""\n'
    '"service","10.0.0.5","443","INFO","HTTP","",""\n'
)


def test_run_explains_empty_findings_and_carries_unfiltered_rows_as_evidence():
    def _write_clean_csv(argv, **kwargs):
        out_path = argv[argv.index("--csvfile") + 1]
        with open(out_path, "w") as f:
            f.write(_CLEAN_CSV)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=_write_clean_csv):
        result = TestSsl().run(target="10.0.0.5")

    assert result["findings"] == []
    assert "2 row(s) checked" in result["note"]
    # The evidence store gets the real unfiltered rows, not another copy
    # of the same empty findings list -- otherwise read_evidence on this
    # result would be a no-op.
    full = result["_full_evidence"]
    assert full["findings"] == []
    assert {"id": "heartbleed", "severity": "OK", "detail": "not vulnerable"} in full["all_rows"]
    assert {"id": "service", "severity": "INFO", "detail": "HTTP"} in full["all_rows"]


def test_extract_facts_reports_worst_severity_onto_derived_host_port():
    tool = TestSsl()
    result = {"findings": [{"id": "cipher_rc4", "severity": "HIGH", "detail": "RC4 ciphers offered"}]}
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{"host": "10.0.0.5", "port": 443, "tls_worst_severity": "HIGH"}]


def test_extract_facts_includes_evidence_id_when_present():
    tool = TestSsl()
    result = {
        "findings": [{"id": "cipher_rc4", "severity": "HIGH", "detail": "RC4 ciphers offered"}],
        "evidence_id": "testssl:10.0.0.5",
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{"host": "10.0.0.5", "port": 443, "tls_worst_severity": "HIGH", "evidence": "testssl:10.0.0.5"}]


def test_extract_evidence_returns_full_findings():
    tool = TestSsl()
    result = {"target": "10.0.0.5", "_full_evidence": {"findings": [{"id": "rc4"}]}}
    target, full = tool.extract_evidence({"target": "10.0.0.5"}, result)
    assert target == "10.0.0.5"
    assert full == {"findings": [{"id": "rc4"}]}


def test_extract_facts_empty_when_no_findings():
    tool = TestSsl()
    assert tool.extract_facts({"target": "10.0.0.5"}, {"findings": []}) == []


def test_extract_facts_includes_evidence_even_when_findings_empty():
    tool = TestSsl()
    result = {"findings": [], "evidence_id": "testssl:10.0.0.5"}
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{"host": "10.0.0.5", "port": 443, "evidence": "testssl:10.0.0.5"}]
