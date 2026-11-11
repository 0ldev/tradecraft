"""Unit tests for Gau Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.gau.execute import RawGauResult
from tradecraft.tools.gau import Gau


class TestGauTool:
    @patch("tradecraft.tools.gau.gau_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawGauResult(error="gau binary not found")
        tool = Gau()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["urls"] == []
        assert res["endpoints"] == []
        assert res["subdomains"] == []
        assert res["parameters"] == []
        assert res["error"] == "gau binary not found"

    @patch("tradecraft.tools.gau.gau_execute.execute")
    @patch("tradecraft.tools.gau.gau_parse.parse_gau_output")
    def test_run_few_results(self, mock_parse, mock_exec):
        mock_exec.return_value = RawGauResult(stdout="http://example.com/a\n", returncode=0)
        mock_parse.return_value = {
            "urls": ["http://example.com/a", "http://example.com/b"],
            "endpoints": ["/a", "/b"],
            "subdomains": ["example.com"],
            "parameters": ["q"],
            "total_urls": 2,
            "total_endpoints": 2,
            "total_subdomains": 1,
            "total_parameters": 1,
        }
        tool = Gau()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["total_urls"] == 2
        assert len(res["urls"]) == 2
        assert res["subdomains"] == ["example.com"]
        assert "omitted_urls" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_urls"] == 2

    @patch("tradecraft.tools.gau.gau_execute.execute")
    @patch("tradecraft.tools.gau.gau_parse.parse_gau_output")
    def test_run_omits_results_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawGauResult(stdout="dummy", returncode=0)
        mock_parse.return_value = {
            "urls": [f"http://example.com/page{i}" for i in range(30)],
            "endpoints": [f"/page{i}" for i in range(25)],
            "subdomains": ["example.com"],
            "parameters": [f"param{i}" for i in range(25)],
            "total_urls": 30,
            "total_endpoints": 25,
            "total_subdomains": 1,
            "total_parameters": 25,
        }
        tool = Gau()
        res = tool.run(target="example.com")
        assert res["total_urls"] == 30
        assert len(res["urls"]) == 20
        assert res["omitted_urls"] == 10
        assert "10 more URLs omitted" in res["note"]
        assert len(res["endpoints"]) == 15
        assert res["omitted_endpoints"] == 10
        assert len(res["parameters"]) == 20
        assert res["omitted_parameters"] == 5
        # Full evidence contains all items
        assert len(res["_full_evidence"]["urls"]) == 30
        assert len(res["_full_evidence"]["endpoints"]) == 25
        assert len(res["_full_evidence"]["parameters"]) == 25

    def test_extract_evidence(self):
        tool = Gau()
        result = {
            "target": "https://example.com:443",
            "total_urls": 1,
            "urls": ["https://example.com/page"],
            "_full_evidence": {"target": "https://example.com:443", "total_urls": 1},
        }
        ev = tool.extract_evidence({"target": "https://example.com:443"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "example.com"
        assert full_data["total_urls"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Gau()
        result = {
            "target": "https://example.com",
            "total_urls": 50,
            "total_endpoints": 12,
            "evidence_id": "gau:example.com",
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        # port 0 is the sentinel for a domain-wide fact with no real port
        # (gau is passive URL discovery, not a probe of any actual
        # service) -- see tradecraft/tools/interactsh.py for the existing
        # convention this matches. A real port like 443 would risk this
        # fact silently merging into (host, 443)'s record alongside an
        # actual HTTPS-port service fact from nmap_scan/httpx_probe on
        # the same apex.
        assert fact["port"] == 0
        assert fact["passive_urls_discovered"] == 50
        assert fact["endpoints_discovered"] == 12
        assert fact["evidence"] == "gau:example.com"

    def test_extract_facts_empty_when_no_urls(self):
        tool = Gau()
        result = {
            "target": "https://example.com",
            "total_urls": 0,
            "total_endpoints": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []
