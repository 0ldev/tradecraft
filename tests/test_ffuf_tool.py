"""Unit tests for Ffuf Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import MagicMock, patch

from tradecraft.adapters.ffuf.execute import CanarySignature, RawFfufResult
from tradecraft.tools.ffuf import Ffuf


class TestFfufTool:
    @patch("tradecraft.tools.ffuf.ffuf_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawFfufResult(error="ffuf executable not found")
        tool = Ffuf()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["endpoints"] == []
        assert res["error"] == "ffuf executable not found"

    @patch("tradecraft.tools.ffuf.ffuf_execute.execute")
    @patch("tradecraft.tools.ffuf.ffuf_parse.parse_results")
    def test_run_few_endpoints(self, mock_parse, mock_exec):
        mock_exec.return_value = RawFfufResult(
            json_output="{}", canary=None, requests_attempted=4614, duration_seconds=12.3
        )
        mock_parse.return_value = [
            {"path": "/admin", "status_code": 200, "length": 100},
            {"path": "/api", "status_code": 200, "length": 200},
        ]
        tool = Ffuf()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["total_found"] == 2
        assert len(res["endpoints"]) == 2
        assert "omitted_endpoints" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_found"] == 2
        # Request-volume/duration telemetry surfaced to the model, not just
        # inferable qualitatively after the fact.
        assert res["requests_sent"] == 4614
        assert res["duration_seconds"] == 12.3

    @patch("tradecraft.tools.ffuf.ffuf_execute.execute")
    @patch("tradecraft.tools.ffuf.ffuf_parse.parse_results")
    def test_run_omits_endpoints_when_exceeding_10(self, mock_parse, mock_exec):
        mock_exec.return_value = RawFfufResult(json_output="{}", canary=None)
        mock_parse.return_value = [
            {"path": f"/path{i}", "status_code": 200, "length": 100 + i}
            for i in range(15)
        ]
        tool = Ffuf()
        res = tool.run(target="https://example.com")
        assert res["total_found"] == 15
        assert len(res["endpoints"]) == 10
        assert res["omitted_endpoints"] == 5
        assert "5 more endpoints omitted" in res["note"]
        # Full evidence retains all 15
        assert len(res["_full_evidence"]["endpoints"]) == 15

    def test_extract_evidence(self):
        tool = Ffuf()
        result = {
            "target": "https://example.com",
            "total_found": 1,
            "endpoints": [{"path": "/admin"}],
            "_full_evidence": {"target": "https://example.com", "total_found": 1},
        }
        ev = tool.extract_evidence({"target": "https://example.com"}, result)
        assert ev is not None
        target, data = ev
        assert target == "example.com"
        assert data["total_found"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Ffuf()
        result = {
            "target": "https://example.com",
            "total_found": 3,
            "evidence_id": "ev_ffuf_123",
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["endpoints_discovered"] == 3
        assert fact["evidence"] == "ev_ffuf_123"

    def test_extract_facts_empty_when_no_endpoints_and_no_evidence(self):
        tool = Ffuf()
        result = {
            "target": "https://example.com",
            "total_found": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []
