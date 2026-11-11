"""Unit tests for Subzy tool, evidence extraction, and facts extraction."""
from unittest.mock import MagicMock, patch

from tradecraft.adapters.subzy.execute import RawSubzyResult
from tradecraft.tools.subzy import Subzy


class TestSubzyTool:
    @patch("tradecraft.tools.subzy.subzy_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawSubzyResult(error="subzy executable not found")
        tool = Subzy()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["vulnerable"] == []
        assert res["error"] == "subzy executable not found"

    @patch("tradecraft.tools.subzy.subzy_execute.execute")
    @patch("tradecraft.tools.subzy.subzy_parse.parse_subzy_output")
    def test_run_success(self, mock_parse, mock_exec):
        mock_exec.return_value = RawSubzyResult(stdout="...", returncode=0)
        mock_parse.return_value = [
            {"subdomain": "sub.example.com", "service": "GitHub Pages", "status": "vulnerable"}
        ]
        tool = Subzy()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["vulnerable_count"] == 1
        assert len(res["vulnerable"]) == 1
        assert "_full_evidence" in res

    def test_extract_evidence(self):
        tool = Subzy()
        result = {
            "target": "sub1.example.com,sub2.example.com",
            "vulnerable": [{"subdomain": "sub1.example.com"}],
            "_full_evidence": {"vulnerable": [{"subdomain": "sub1.example.com"}]},
        }
        ev = tool.extract_evidence({"target": "sub1.example.com,sub2.example.com"}, result)
        assert ev is not None
        target, data, aliases = ev
        assert target == "sub1.example.com"
        assert aliases == ["sub2.example.com"]
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Subzy()
        result = {
            "vulnerable": [
                {
                    "subdomain": "takeover.example.com",
                    "service": "AWS S3",
                }
            ],
            "evidence_id": "subzy:example.com",
        }
        facts = tool.extract_facts({"target": "example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "takeover.example.com"
        assert fact["port"] == 443
        assert fact["subdomain_takeover"] == "AWS S3"
        assert fact["evidence"] == "subzy:example.com"

    def test_extract_facts_empty_when_no_vulnerabilities(self):
        tool = Subzy()
        result = {"vulnerable": []}
        facts = tool.extract_facts({"target": "example.com"}, result)
        assert facts == []
