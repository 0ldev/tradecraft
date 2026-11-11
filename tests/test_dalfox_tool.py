"""Unit tests for Dalfox Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.dalfox.execute import RawDalfoxResult
from tradecraft.tools.dalfox import Dalfox


class TestDalfoxTool:
    @patch("tradecraft.tools.dalfox.dalfox_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawDalfoxResult(error="dalfox binary not found")
        tool = Dalfox()
        res = tool.run(target="https://example.com/search?q=1")
        assert res["target"] == "https://example.com/search?q=1"
        assert res["findings"] == []
        assert res["total_findings"] == 0
        assert res["vulnerable_count"] == 0
        assert res["error"] == "dalfox binary not found"

    @patch("tradecraft.tools.dalfox.dalfox_execute.execute")
    @patch("tradecraft.tools.dalfox.dalfox_parse.parse_dalfox_output")
    def test_run_vulnerable(self, mock_parse, mock_exec):
        mock_exec.return_value = RawDalfoxResult(returncode=0)
        mock_parse.return_value = {
            "findings": [
                {
                    "type": "V",
                    "type_description": "Vulnerable",
                    "param": "q",
                    "severity": "High",
                    "payload": "<script>alert(1)</script>",
                    "cwe": "CWE-79",
                    "evidence": "DOM verification succeeded",
                    "poc": "https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                    "method": "GET",
                    "inject_type": "inHTML",
                    "confidence": "high",
                }
            ],
            "total_findings": 1,
            "vulnerable_count": 1,
            "reflected_count": 0,
            "dom_count": 0,
            "meta": {"dalfox_version": "3.2.4"},
        }
        tool = Dalfox()
        res = tool.run(target="https://example.com/search?q=1", parameter="q")
        assert res["target"] == "https://example.com/search?q=1"
        assert res["parameter"] == "q"
        assert res["total_findings"] == 1
        assert res["vulnerable_count"] == 1
        assert len(res["findings"]) == 1
        assert "omitted_findings" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["vulnerable_count"] == 1

    @patch("tradecraft.tools.dalfox.dalfox_execute.execute")
    @patch("tradecraft.tools.dalfox.dalfox_parse.parse_dalfox_output")
    def test_run_omits_findings_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawDalfoxResult(returncode=0)
        mock_parse.return_value = {
            "findings": [
                {"type": "R", "param": f"p_{i}", "severity": "Medium", "payload": "<test>"}
                for i in range(15)
            ],
            "total_findings": 15,
            "vulnerable_count": 0,
            "reflected_count": 15,
            "dom_count": 0,
            "meta": {},
        }
        tool = Dalfox()
        res = tool.run(target="https://example.com/search?q=1")
        assert res["total_findings"] == 15
        assert len(res["findings"]) == 10
        assert res["omitted_findings"] == 5
        assert "5 more findings omitted" in res["note"]
        assert len(res["_full_evidence"]["findings"]) == 15

    def test_extract_evidence(self):
        tool = Dalfox()
        result = {
            "target": "https://sub.example.com:8443/search?q=1",
            "findings": [{"param": "q"}],
            "_full_evidence": {"raw": "data"},
        }
        extracted = tool.extract_evidence(
            {"target": "https://sub.example.com:8443/search?q=1"},
            result,
        )
        assert extracted is not None
        canonical, full = extracted
        assert canonical == "sub.example.com"
        assert full == {"raw": "data"}
        assert "_full_evidence" not in result

    def test_extract_evidence_empty(self):
        tool = Dalfox()
        assert tool.extract_evidence({}, {}) is None

    def test_extract_facts_vulnerable(self):
        tool = Dalfox()
        result = {
            "target": "https://example.com/search?q=1",
            "total_findings": 2,
            "vulnerable_count": 1,
            "evidence_id": "ev_dalfox_123",
        }
        facts = tool.extract_facts({"target": "https://example.com/search?q=1"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["xss_tested"] is True
        assert fact["dalfox_findings"] == 2
        assert fact["dalfox_xss_vulnerable"] is True
        assert fact["evidence"] == "ev_dalfox_123"

    def test_extract_facts_reflected_only(self):
        tool = Dalfox()
        result = {
            "target": "http://example.com:8080/search?q=1",
            "total_findings": 1,
            "vulnerable_count": 0,
        }
        facts = tool.extract_facts({"target": "http://example.com:8080/search?q=1"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 8080
        assert fact["xss_tested"] is True
        assert fact["dalfox_findings"] == 1
        assert "dalfox_xss_vulnerable" not in fact

    def test_extract_facts_clean(self):
        tool = Dalfox()
        result = {
            "target": "https://example.com/search?q=1",
            "total_findings": 0,
            "vulnerable_count": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com/search?q=1"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "example.com"
        assert facts[0]["port"] == 443
        assert facts[0]["xss_tested"] is True

    def test_error_result_produces_no_facts(self):
        tool = Dalfox()
        facts = tool.extract_facts({"target": "https://example.com"}, {"error": "dalfox timed out"})
        assert facts == []
