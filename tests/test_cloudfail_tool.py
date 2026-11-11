"""Unit tests for Cloudfail Tool glue, facts extraction, and evidence extraction."""
from unittest.mock import patch

from tradecraft.adapters.cloudfail.execute import RawCloudfailResult
from tradecraft.tools.cloudfail import Cloudfail


class TestCloudfailTool:
    @patch("tradecraft.tools.cloudfail.run_cloudfail")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawCloudfailResult(error="cloudfail binary not found on PATH")
        tool = Cloudfail()
        res = tool.run(target="example.com")
        assert res["target"] == "example.com"
        assert res["is_cloudflare"] is False
        assert res["origin_unmasked"] is False
        assert res["error"] == "cloudfail binary not found on PATH"

    @patch("tradecraft.tools.cloudfail.run_cloudfail")
    @patch("tradecraft.tools.cloudfail.parse_cloudfail_output")
    def test_run_clean_direct_target(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCloudfailResult(stdout="dummy", returncode=0, target="examplepaint.com.br")
        mock_parse.return_value = {
            "target": "examplepaint.com.br",
            "server_ip": "192.0.2.10",
            "is_cloudflare": False,
            "origin_unmasked": False,
            "unmasked_origin_ips": [],
            "unmasked_subdomains": [],
            "cloudflare_subdomains": [],
        }
        tool = Cloudfail()
        res = tool.run(target="examplepaint.com.br")
        assert res["target"] == "examplepaint.com.br"
        assert res["server_ip"] == "192.0.2.10"
        assert res["is_cloudflare"] is False
        assert res["origin_unmasked"] is False
        assert "_full_evidence" in res

    @patch("tradecraft.tools.cloudfail.run_cloudfail")
    @patch("tradecraft.tools.cloudfail.parse_cloudfail_output")
    def test_run_cloudflare_unmasked_with_omission(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCloudfailResult(stdout="dummy", returncode=0, target="exampleauto.com.br")
        mock_parse.return_value = {
            "target": "exampleauto.com.br",
            "server_ip": "104.26.8.9",
            "is_cloudflare": True,
            "origin_unmasked": True,
            "unmasked_origin_ips": ["203.0.113.69"],
            "unmasked_subdomains": [{"subdomain": f"sub{i}.domain.com", "ip": f"1.1.1.{i}"} for i in range(15)],
            "cloudflare_subdomains": [f"cf{i}.domain.com" for i in range(12)],
        }
        tool = Cloudfail()
        res = tool.run(target="exampleauto.com.br")
        assert res["is_cloudflare"] is True
        assert res["origin_unmasked"] is True
        assert res["unmasked_origin_ips"] == ["203.0.113.69"]
        assert len(res["unmasked_subdomains"]) == 10
        assert res["omitted_unmasked_subdomains"] == 5
        assert len(res["cloudflare_subdomains"]) == 10
        assert res["omitted_cloudflare_subdomains"] == 2
        assert len(res["_full_evidence"]["unmasked_subdomains"]) == 15

    def test_extract_evidence(self):
        tool = Cloudfail()
        result = {
            "target": "https://exampleauto.com.br",
            "is_cloudflare": True,
            "_full_evidence": {"target": "exampleauto.com.br", "is_cloudflare": True},
        }
        ev = tool.extract_evidence({"target": "https://exampleauto.com.br"}, result)
        assert ev is not None
        canonical, full = ev
        assert canonical == "exampleauto.com.br"
        assert full["is_cloudflare"] is True
        assert "_full_evidence" not in result

    def test_extract_facts_when_direct_host(self):
        tool = Cloudfail()
        result = {
            "target": "examplepaint.com.br",
            "is_cloudflare": False,
            "origin_unmasked": False,
            "unmasked_origin_ips": [],
        }
        facts = tool.extract_facts({"target": "examplepaint.com.br"}, result)
        assert facts == []

    def test_extract_facts_when_cloudflare_and_unmasked(self):
        tool = Cloudfail()
        result = {
            "target": "exampleauto.com.br",
            "is_cloudflare": True,
            "origin_unmasked": True,
            "unmasked_origin_ips": ["203.0.113.69"],
            "evidence_id": "cloudfail:exampleauto.com.br",
        }
        facts = tool.extract_facts({"target": "exampleauto.com.br"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "exampleauto.com.br"
        assert fact["cloudflare_protected"] is True
        assert fact["origin_unmasked_ips"] == ["203.0.113.69"]
        assert fact["evidence"] == "cloudfail:exampleauto.com.br"
