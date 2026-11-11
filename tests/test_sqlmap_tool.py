"""Unit tests for Sqlmap Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.sqlmap.execute import RawSqlmapResult
from tradecraft.tools.sqlmap import Sqlmap


class TestSqlmapTool:
    @patch("tradecraft.tools.sqlmap.sqlmap_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawSqlmapResult(error="sqlmap binary not found")
        tool = Sqlmap()
        res = tool.run(target="https://example.com/item?id=1")
        assert res["target"] == "https://example.com/item?id=1"
        assert res["injectable"] is False
        assert res["vulnerabilities"] == []
        assert res["error"] == "sqlmap binary not found"

    @patch("tradecraft.tools.sqlmap.sqlmap_execute.execute")
    @patch("tradecraft.tools.sqlmap.sqlmap_parse.parse_sqlmap_output")
    def test_run_vulnerable(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSqlmapResult(returncode=0, duration_seconds=8.7)
        mock_parse.return_value = {
            "injectable": True,
            "dbms": "PostgreSQL",
            "total_vulnerabilities": 1,
            "vulnerabilities": [
                {
                    "parameter": "id",
                    "place": "GET",
                    "techniques": "error-based",
                    "title": "PostgreSQL error-based",
                    "payload": "id=1 AND 1=1",
                }
            ],
        }
        tool = Sqlmap()
        res = tool.run(target="https://example.com/item?id=1", parameter="id")
        assert res["target"] == "https://example.com/item?id=1"
        assert res["parameter"] == "id"
        assert res["injectable"] is True
        assert res["dbms"] == "PostgreSQL"
        assert res["total_vulnerabilities"] == 1
        assert "omitted_vulnerabilities" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["injectable"] is True
        assert res["duration_seconds"] == 8.7

    @patch("tradecraft.tools.sqlmap.sqlmap_execute.execute")
    @patch("tradecraft.tools.sqlmap.sqlmap_parse.parse_sqlmap_output")
    def test_run_omits_vulnerabilities_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSqlmapResult(returncode=0)
        mock_parse.return_value = {
            "injectable": True,
            "dbms": "MySQL",
            "total_vulnerabilities": 15,
            "vulnerabilities": [
                {"parameter": f"p_{i}", "place": "GET", "techniques": "blind"} for i in range(15)
            ],
        }
        tool = Sqlmap()
        res = tool.run(target="https://example.com/api")
        assert res["total_vulnerabilities"] == 15
        assert len(res["vulnerabilities"]) == 10
        assert res["omitted_vulnerabilities"] == 5
        assert "5 more injection vulnerabilities omitted" in res["note"]
        assert len(res["_full_evidence"]["vulnerabilities"]) == 15

    def test_extract_evidence(self):
        tool = Sqlmap()
        result = {
            "target": "https://example.com:443/item?id=1",
            "parameter": "id",
            "injectable": True,
            "total_vulnerabilities": 1,
            "vulnerabilities": [{"parameter": "id"}],
            "_full_evidence": {
                "target": "https://example.com:443/item?id=1",
                "injectable": True,
                "vulnerabilities": [{"parameter": "id"}],
            },
        }
        ev = tool.extract_evidence({"target": "https://example.com:443/item?id=1"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "example.com"
        assert full_data["injectable"] is True
        assert "_full_evidence" not in result

    def test_extract_facts_vulnerable(self):
        tool = Sqlmap()
        result = {
            "target": "https://example.com/item?id=1",
            "injectable": True,
            "dbms": "MySQL",
            "evidence_id": "evidence:sqlmap:example.com:1",
        }
        facts = tool.extract_facts({"target": "https://example.com/item?id=1"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["sqli_injectable"] is True
        assert fact["sqli_dbms"] == "MySQL"
        assert fact["evidence"] == "evidence:sqlmap:example.com:1"

    def test_extract_facts_clean(self):
        tool = Sqlmap()
        result = {
            "target": "https://example.com/item?id=1",
            "injectable": False,
            "evidence_id": "evidence:sqlmap:example.com:1",
        }
        facts = tool.extract_facts({"target": "https://example.com/item?id=1"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["sqli_tested"] is True
        assert fact["evidence"] == "evidence:sqlmap:example.com:1"

    def test_error_result_produces_no_facts(self):
        tool = Sqlmap()
        facts = tool.extract_facts({"target": "https://example.com"}, {"error": "sqlmap timed out"})
        assert facts == []
