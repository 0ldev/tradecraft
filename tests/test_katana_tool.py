"""Unit tests for Katana Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.katana.execute import RawKatanaResult
from tradecraft.tools.katana import Katana


class TestKatanaTool:
    @patch("tradecraft.tools.katana.katana_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawKatanaResult(error="katana binary not found")
        tool = Katana()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["endpoints"] == []
        assert res["parameters"] == []
        assert res["error"] == "katana binary not found"

    @patch("tradecraft.tools.katana.katana_execute.execute")
    @patch("tradecraft.tools.katana.katana_parse.parse_katana_output")
    def test_run_few_endpoints(self, mock_parse, mock_exec):
        mock_exec.return_value = RawKatanaResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "endpoints": [
                {"endpoint": "https://example.com/admin", "path": "/admin", "method": "GET"},
                {"endpoint": "https://example.com/login", "path": "/login", "method": "POST"},
            ],
            "parameters": ["q", "token"],
            "total_endpoints": 2,
            "total_parameters": 2,
        }
        tool = Katana()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["total_endpoints"] == 2
        assert res["total_parameters"] == 2
        assert len(res["endpoints"]) == 2
        assert res["parameters"] == ["q", "token"]
        assert "omitted_endpoints" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_endpoints"] == 2

    @patch("tradecraft.tools.katana.katana_execute.execute")
    @patch("tradecraft.tools.katana.katana_parse.parse_katana_output")
    def test_run_omits_endpoints_when_exceeding_15(self, mock_parse, mock_exec):
        mock_exec.return_value = RawKatanaResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "endpoints": [
                {"endpoint": f"https://example.com/page{i}", "path": f"/page{i}", "method": "GET"}
                for i in range(25)
            ],
            "parameters": [f"param{i}" for i in range(30)],
            "total_endpoints": 25,
            "total_parameters": 30,
        }
        tool = Katana()
        res = tool.run(target="https://example.com")
        assert res["total_endpoints"] == 25
        assert len(res["endpoints"]) == 15
        assert res["omitted_endpoints"] == 10
        assert "10 more endpoints omitted" in res["note"]
        assert len(res["parameters"]) == 20
        assert res["omitted_parameters"] == 10
        # Full evidence contains all 25 endpoints and 30 parameters
        assert len(res["_full_evidence"]["endpoints"]) == 25
        assert len(res["_full_evidence"]["parameters"]) == 30

    @patch("tradecraft.tools.katana.katana_execute.execute")
    @patch("tradecraft.tools.katana.katana_parse.parse_katana_output")
    def test_run_with_headless(self, mock_parse, mock_exec):
        mock_exec.return_value = RawKatanaResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "endpoints": [{"endpoint": "https://example.com/app", "path": "/app", "method": "GET"}],
            "parameters": ["session_id"],
            "total_endpoints": 1,
            "total_parameters": 1,
        }
        tool = Katana()
        res = tool.run(target="https://example.com", headless=True)
        assert res["total_endpoints"] == 1
        assert res["endpoints"] == [{"endpoint": "https://example.com/app", "path": "/app", "method": "GET"}]
        assert res["parameters"] == ["session_id"]
        mock_exec.assert_called_once_with(
            target="https://example.com",
            depth=2,
            js_crawl=True,
            crawl_duration=15,
            headless=True,
        )

    def test_extract_evidence(self):
        tool = Katana()
        result = {
            "target": "https://example.com:443",
            "total_endpoints": 1,
            "endpoints": [{"path": "/admin"}],
            "_full_evidence": {"target": "https://example.com:443", "total_endpoints": 1},
        }
        ev = tool.extract_evidence({"target": "https://example.com:443"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "example.com"
        assert full_data["total_endpoints"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Katana()
        result = {
            "target": "https://example.com",
            "total_endpoints": 42,
            "total_parameters": 5,
            "parameters": ["q", "redirect", "id"],
            "evidence_id": "katana:example.com",
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["endpoints_crawled"] == 42
        assert fact["params_discovered"] == 5
        assert fact["params_sample"] == "id,q,redirect"
        assert fact["evidence"] == "katana:example.com"

    def test_extract_facts_empty_when_no_endpoints(self):
        tool = Katana()
        result = {
            "target": "https://example.com",
            "total_endpoints": 0,
            "total_parameters": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []
