"""Unit tests for Searchsploit Tool glue, facts extraction, and evidence extraction."""
from unittest.mock import patch

from tradecraft.adapters.searchsploit.execute import RawSearchsploitResult
from tradecraft.tools.searchsploit import Searchsploit


class TestSearchsploitTool:
    @patch("tradecraft.tools.searchsploit.run_searchsploit")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawSearchsploitResult(error="searchsploit binary not found on PATH")
        tool = Searchsploit()
        res = tool.run(query="Apache")
        assert res["query"] == "Apache"
        assert res["total_exploits"] == 0
        assert res["error"] == "searchsploit binary not found on PATH"

    @patch("tradecraft.tools.searchsploit.run_searchsploit")
    @patch("tradecraft.tools.searchsploit.parse_searchsploit_output")
    def test_run_search_success_small(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSearchsploitResult(stdout="dummy", returncode=0, query="Apache 2.4.49")
        mock_parse.return_value = {
            "mode": "search",
            "query": "Apache 2.4.49",
            "total_exploits": 2,
            "exploits": [
                {"edb_id": "50383", "title": "Apache RCE", "codes": "CVE-2021-41773"},
                {"edb_id": "50512", "title": "Apache RCE 2", "codes": "CVE-2021-42013"},
            ],
        }
        tool = Searchsploit()
        res = tool.run(query="Apache 2.4.49", target="example.com")
        assert res["mode"] == "search"
        assert res["total_exploits"] == 2
        assert len(res["exploits"]) == 2
        assert "_full_evidence" in res
        assert len(res["_full_evidence"]["parsed"]["exploits"]) == 2

    @patch("tradecraft.tools.searchsploit.run_searchsploit")
    @patch("tradecraft.tools.searchsploit.parse_searchsploit_output")
    def test_run_search_with_omission(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSearchsploitResult(stdout="dummy", returncode=0, query="WordPress")
        mock_parse.return_value = {
            "mode": "search",
            "query": "WordPress",
            "total_exploits": 15,
            "exploits": [
                {"edb_id": str(i), "title": f"Exploit {i}", "codes": f"CVE-2020-{i}"}
                for i in range(15)
            ],
        }
        tool = Searchsploit()
        res = tool.run(query="WordPress")
        assert res["total_exploits"] == 15
        assert len(res["exploits"]) == 10
        assert res["omitted_exploits"] == 5
        assert "5 more exploits omitted" in res["note"]

    @patch("tradecraft.tools.searchsploit.run_searchsploit")
    @patch("tradecraft.tools.searchsploit.parse_searchsploit_output")
    def test_run_examine_mode(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSearchsploitResult(stdout="dummy", returncode=0, edb_id="50383")
        mock_parse.return_value = {
            "mode": "examine",
            "edb_id": "50383",
            "title": "Apache RCE",
            "url": "https://www.exploit-db.com/exploits/50383",
            "codes": "CVE-2021-41773",
            "verified": True,
            "path": "/opt/exploitdb/exploits/50383.sh",
            "poc_content": "curl PoC content",
        }
        tool = Searchsploit()
        res = tool.run(edb_id="50383")
        assert res["mode"] == "examine"
        assert res["edb_id"] == "50383"
        assert res["poc_content"] == "curl PoC content"

    def test_extract_evidence(self):
        tool = Searchsploit()
        result = {
            "query": "Apache 2.4.49",
            "target": "example.com",
            "_full_evidence": {"query": "Apache 2.4.49", "target": "example.com"},
        }
        ev = tool.extract_evidence({"target": "example.com", "query": "Apache 2.4.49"}, result)
        assert ev is not None
        canonical, full = ev
        assert canonical == "example.com"
        assert full["query"] == "Apache 2.4.49"
        assert "_full_evidence" not in result

    def test_extract_facts_when_no_target(self):
        tool = Searchsploit()
        result = {"query": "Apache", "total_exploits": 5}
        facts = tool.extract_facts({"query": "Apache"}, result)
        assert facts == []

    def test_extract_facts_when_target_provided(self):
        tool = Searchsploit()
        result = {"target": "example.com:80", "total_exploits": 3, "evidence_id": "searchsploit:example.com"}
        facts = tool.extract_facts({"target": "example.com:80", "query": "Apache"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 80
        assert fact["known_exploits_count"] == 3
        assert fact["evidence"] == "searchsploit:example.com"
