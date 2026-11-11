"""Unit tests for Arjun Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.arjun.execute import RawArjunResult
from tradecraft.tools.arjun import Arjun


class TestArjunTool:
    @patch("tradecraft.tools.arjun.arjun_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawArjunResult(error="arjun binary not found")
        tool = Arjun()
        res = tool.run(target="https://examplepaint.com.br")
        assert res["target"] == "https://examplepaint.com.br"
        assert res["parameters"] == []
        assert res["error"] == "arjun binary not found"

    @patch("tradecraft.tools.arjun.arjun_execute.execute")
    @patch("tradecraft.tools.arjun.arjun_parse.parse_arjun_output")
    def test_run_few_results(self, mock_parse, mock_exec):
        mock_exec.return_value = RawArjunResult(stdout="dummy", returncode=0)
        mock_parse.return_value = {
            "parameters": ["_action", "token"],
            "total_parameters": 2,
        }
        tool = Arjun()
        res = tool.run(target="https://examplepaint.com.br", path="/login.php")
        assert res["target"] == "https://examplepaint.com.br"
        assert res["path"] == "/login.php"
        assert res["total_parameters"] == 2
        assert res["parameters"] == ["_action", "token"]
        assert "omitted_parameters" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_parameters"] == 2

    @patch("tradecraft.tools.arjun.arjun_execute.execute")
    @patch("tradecraft.tools.arjun.arjun_parse.parse_arjun_output")
    def test_run_omits_parameters_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawArjunResult(stdout="dummy", returncode=0)
        mock_parse.return_value = {
            "parameters": [f"param_{i}" for i in range(30)],
            "total_parameters": 30,
        }
        tool = Arjun()
        res = tool.run(target="https://examplepaint.com.br")
        assert res["total_parameters"] == 30
        assert len(res["parameters"]) == 20
        assert res["omitted_parameters"] == 10
        assert "10 more parameters omitted" in res["note"]
        assert len(res["_full_evidence"]["parameters"]) == 30

    def test_extract_evidence(self):
        tool = Arjun()
        result = {
            "target": "https://examplepaint.com.br:443",
            "path": "/",
            "method": "GET",
            "total_parameters": 2,
            "parameters": ["_action", "token"],
            "_full_evidence": {
                "target": "https://examplepaint.com.br:443",
                "total_parameters": 2,
                "parameters": ["_action", "token"],
            },
        }
        ev = tool.extract_evidence({"target": "https://examplepaint.com.br:443"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "examplepaint.com.br"
        assert full_data["total_parameters"] == 2
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Arjun()
        result = {
            "target": "https://examplepaint.com.br",
            "total_parameters": 5,
            "parameters": ["user", "debug", "action"],
            "evidence_id": "evidence:arjun:examplepaint.com.br:1",
        }
        facts = tool.extract_facts({"target": "https://examplepaint.com.br"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "examplepaint.com.br"
        assert fact["port"] == 443
        assert fact["arjun_params_discovered"] == 5
        assert fact["arjun_params_sample"] == "action,debug,user"
        assert fact["evidence"] == "evidence:arjun:examplepaint.com.br:1"

    def test_extract_facts_records_arjun_tested_when_no_parameters(self):
        tool = Arjun()
        result = {
            "target": "https://examplepaint.com.br",
            "total_parameters": 0,
        }
        facts = tool.extract_facts({"target": "https://examplepaint.com.br"}, result)
        assert facts == [{"host": "examplepaint.com.br", "port": 443, "arjun_tested": True}]
