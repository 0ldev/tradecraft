"""Unit tests for Cloudenum Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.cloudenum.execute import RawCloudEnumResult
from tradecraft.tools.cloudenum import Cloudenum


class TestCloudenumTool:
    @patch("tradecraft.tools.cloudenum.cloudenum_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawCloudEnumResult(error="cloud_enum binary not found", keyword="examplepaint")
        tool = Cloudenum()
        res = tool.run(target="examplepaint.com.br")
        assert res["target"] == "examplepaint.com.br"
        assert res["keyword"] == "examplepaint"
        assert res["resources"] == []
        assert res["total_resources"] == 0
        assert res["public_count"] == 0
        assert res["error"] == "cloud_enum binary not found"

    @patch("tradecraft.tools.cloudenum.cloudenum_execute.execute")
    @patch("tradecraft.tools.cloudenum.cloudenum_parse.parse_cloudenum_output")
    def test_run_success(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCloudEnumResult(returncode=0, keyword="exampleauto")
        mock_parse.return_value = {
            "resources": [
                {
                    "platform": "azure",
                    "resource": "https://exampleauto.blob.core.windows.net/public",
                    "message": "Open Blob Container",
                    "access": "public",
                    "is_public": True,
                }
            ],
            "total_resources": 1,
            "public_count": 1,
            "protected_count": 0,
            "disabled_count": 0,
            "by_platform": {"azure": 1},
        }
        tool = Cloudenum()
        res = tool.run(target="https://exampleauto.com.br")
        assert res["target"] == "https://exampleauto.com.br"
        assert res["keyword"] == "exampleauto"
        assert res["total_resources"] == 1
        assert res["public_count"] == 1
        assert len(res["resources"]) == 1
        assert "omitted_resources" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["public_count"] == 1

    @patch("tradecraft.tools.cloudenum.cloudenum_execute.execute")
    @patch("tradecraft.tools.cloudenum.cloudenum_parse.parse_cloudenum_output")
    def test_run_omits_resources_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawCloudEnumResult(returncode=0, keyword="bigcorp")
        mock_parse.return_value = {
            "resources": [
                {"platform": "aws", "resource": f"s3://bucket_{i}", "is_public": False, "access": "protected"}
                for i in range(25)
            ],
            "total_resources": 25,
            "public_count": 0,
            "protected_count": 25,
            "disabled_count": 0,
            "by_platform": {"aws": 25},
        }
        tool = Cloudenum()
        res = tool.run(target="bigcorp.com")
        assert res["total_resources"] == 25
        assert len(res["resources"]) == 15
        assert res["omitted_resources"] == 10
        assert "10 more cloud resources omitted" in res["note"]
        assert len(res["_full_evidence"]["resources"]) == 25

    def test_extract_evidence(self):
        tool = Cloudenum()
        result = {
            "target": "examplepaint.com.br",
            "keyword": "examplepaint",
            "resources": [{"platform": "aws"}],
            "_full_evidence": {"raw": "data", "keyword": "examplepaint"},
        }
        extracted = tool.extract_evidence({"target": "examplepaint.com.br"}, result)
        assert extracted is not None
        canonical, full = extracted
        assert canonical == "examplepaint"
        assert full == {"raw": "data", "keyword": "examplepaint"}
        assert "_full_evidence" not in result

    def test_extract_evidence_empty(self):
        tool = Cloudenum()
        assert tool.extract_evidence({}, {}) is None

    def test_extract_facts_public_bucket(self):
        tool = Cloudenum()
        result = {
            "target": "exampleauto.com.br",
            "total_resources": 3,
            "public_count": 1,
            "evidence_id": "ev_cloud_123",
        }
        facts = tool.extract_facts({"target": "exampleauto.com.br"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "exampleauto.com.br"
        # port 0 is the sentinel for a domain-wide fact with no real port
        # (cloud_enum searches third-party cloud storage by keyword, not
        # the target's own port 443) -- see tradecraft/tools/interactsh.py
        # for the existing convention this matches. A real port like 443
        # would risk this fact silently merging into (host, 443)'s
        # record alongside an actual HTTPS-port service fact from
        # nmap_scan/httpx_probe on the same apex.
        assert fact["port"] == 0
        assert fact["cloud_assets_found"] == 3
        assert fact["cloud_public_buckets"] == 1
        assert fact["evidence"] == "ev_cloud_123"

    def test_extract_facts_empty_when_no_resources(self):
        tool = Cloudenum()
        result = {
            "target": "examplepaint.com.br",
            "total_resources": 0,
            "public_count": 0,
        }
        facts = tool.extract_facts({"target": "examplepaint.com.br"}, result)
        assert facts == []
