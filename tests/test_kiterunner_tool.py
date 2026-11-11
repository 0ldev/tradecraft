"""Unit tests for Kiterunner Tool glue, facts extraction, and evidence extraction."""
from unittest.mock import patch

from tradecraft.adapters.kiterunner.execute import RawKiterunnerResult
from tradecraft.tools.kiterunner import Kiterunner


class TestKiterunnerTool:
    @patch("tradecraft.tools.kiterunner.run_kiterunner")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawKiterunnerResult(error="kiterunner (kr) binary not found on PATH")
        tool = Kiterunner()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["total_endpoints"] == 0
        assert res["endpoints"] == []
        assert res["error"] == "kiterunner (kr) binary not found on PATH"

    @patch("tradecraft.tools.kiterunner.run_kiterunner")
    @patch("tradecraft.tools.kiterunner.parse_kiterunner_output")
    def test_run_success_small(self, mock_parse, mock_exec):
        mock_exec.return_value = RawKiterunnerResult(stdout="dummy", returncode=0, target_url="https://example.com")
        mock_parse.return_value = {
            "target": "https://example.com",
            "total_endpoints": 2,
            "endpoints": [
                {"path": "/api/v1/users", "method": "GET", "status_code": 200, "length": 150},
                {"path": "/api/v1/auth", "method": "POST", "status_code": 200, "length": 80},
            ],
        }
        tool = Kiterunner()
        res = tool.run(target="https://example.com")
        assert res["total_endpoints"] == 2
        assert len(res["endpoints"]) == 2
        assert "_full_evidence" in res
        assert len(res["_full_evidence"]["endpoints"]) == 2

    @patch("tradecraft.tools.kiterunner.run_kiterunner")
    @patch("tradecraft.tools.kiterunner.parse_kiterunner_output")
    def test_run_success_with_omission(self, mock_parse, mock_exec):
        mock_exec.return_value = RawKiterunnerResult(stdout="dummy", returncode=0, target_url="https://example.com")
        mock_parse.return_value = {
            "target": "https://example.com",
            "total_endpoints": 20,
            "endpoints": [
                {"path": f"/api/v1/resource{i}", "method": "GET", "status_code": 200, "length": 100}
                for i in range(20)
            ],
        }
        tool = Kiterunner()
        res = tool.run(target="https://example.com")
        assert res["total_endpoints"] == 20
        assert len(res["endpoints"]) == 15
        assert res["omitted_endpoints"] == 5
        assert "5 more endpoints omitted" in res["note"]
        assert len(res["_full_evidence"]["endpoints"]) == 20

    def test_extract_evidence(self):
        tool = Kiterunner()
        result = {
            "target": "https://api.example.com",
            "total_endpoints": 1,
            "_full_evidence": {"target": "https://api.example.com", "total_endpoints": 1},
        }
        ev = tool.extract_evidence({"target": "https://api.example.com"}, result)
        assert ev is not None
        canonical, full = ev
        assert canonical == "api.example.com"
        assert full["total_endpoints"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts_when_empty(self):
        tool = Kiterunner()
        result = {"target": "https://example.com", "total_endpoints": 0, "endpoints": []}
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []

    def test_extract_facts_when_endpoints_found(self):
        tool = Kiterunner()
        result = {
            "target": "https://example.com:8443",
            "total_endpoints": 5,
            "evidence_id": "kiterunner:example.com",
        }
        facts = tool.extract_facts({"target": "https://example.com:8443"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 8443
        assert fact["api_endpoints_count"] == 5
        assert fact["evidence"] == "kiterunner:example.com"
