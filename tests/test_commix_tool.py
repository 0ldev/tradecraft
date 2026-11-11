"""Unit tests for Commix Tool glue, facts extraction, and evidence extraction."""
from unittest.mock import patch

from tradecraft.adapters.commix.execute import RawCommixResult
from tradecraft.tools.commix import Commix


class TestCommixTool:
    @patch("tradecraft.tools.commix.run_commix")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawCommixResult(error="commix binary not found on PATH")
        tool = Commix()
        res = tool.run(target="http://example.com/test", parameter="q")
        assert res["target"] == "http://example.com/test"
        assert res["parameter"] == "q"
        assert res["vulnerable"] is False
        assert res["total_injections"] == 0
        assert res["error"] == "commix binary not found on PATH"

    @patch("tradecraft.tools.commix.run_commix")
    @patch("tradecraft.tools.commix.parse_commix_output")
    def test_run_clean_result(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCommixResult(stdout="dummy", returncode=0, target_url="http://example.com")
        mock_parse.return_value = {
            "target": "http://example.com/test",
            "parameter": "id",
            "vulnerable": False,
            "total_injections": 0,
            "injections": [],
            "target_os": "unknown",
        }
        tool = Commix()
        res = tool.run(target="http://example.com/test", parameter="id")
        assert res["vulnerable"] is False
        assert res["total_injections"] == 0
        assert res["injections"] == []
        assert "_full_evidence" in res
        assert res["_full_evidence"]["vulnerable"] is False

    @patch("tradecraft.tools.commix.run_commix")
    @patch("tradecraft.tools.commix.parse_commix_output")
    def test_run_vulnerable_result_with_omission(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCommixResult(stdout="dummy", logs_content="logs", returncode=0)
        mock_parse.return_value = {
            "target": "http://example.com/vuln",
            "parameter": "cmd",
            "vulnerable": True,
            "total_injections": 8,
            "target_os": "Unix",
            "injections": [
                {"technique": f"Tech{i}", "type": "injection", "payload": f"payload{i}"}
                for i in range(8)
            ],
        }
        tool = Commix()
        res = tool.run(target="http://example.com/vuln", parameter="cmd")
        assert res["vulnerable"] is True
        assert res["total_injections"] == 8
        assert len(res["injections"]) == 5
        assert res["omitted_injections"] == 3
        assert "3 more injection points omitted" in res["note"]
        assert len(res["_full_evidence"]["injections"]) == 8

    def test_extract_evidence(self):
        tool = Commix()
        result = {
            "target": "http://example.com/vuln",
            "vulnerable": True,
            "_full_evidence": {"target": "http://example.com/vuln", "vulnerable": True},
        }
        ev = tool.extract_evidence({"target": "http://example.com/vuln"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "example.com"
        assert full_data["vulnerable"] is True
        assert "_full_evidence" not in result

    def test_extract_facts_when_clean(self):
        tool = Commix()
        result = {"target": "http://example.com/clean", "vulnerable": False, "total_injections": 0}
        facts = tool.extract_facts({"target": "http://example.com/clean"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "example.com"
        assert facts[0]["port"] == 80
        assert facts[0]["cmdi_tested"] is True

    def test_error_result_produces_no_facts(self):
        tool = Commix()
        facts = tool.extract_facts({"target": "http://example.com"}, {"error": "commix timed out"})
        assert facts == []

    def test_extract_facts_when_vulnerable(self):
        tool = Commix()
        result = {
            "target": "http://example.com/vuln",
            "vulnerable": True,
            "total_injections": 2,
            "target_os": "Unix",
            "evidence_id": "commix:example.com",
        }
        facts = tool.extract_facts({"target": "http://example.com/vuln"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 80
        assert fact["cmdi_tested"] is True
        assert fact["command_injection_vulnerable"] is True
        assert fact["command_injection_points"] == 2
        assert fact["target_os"] == "Unix"
        assert fact["evidence"] == "commix:example.com"
