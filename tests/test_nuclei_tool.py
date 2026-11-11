"""Unit tests for Nuclei Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.nuclei.execute import RawNucleiResult
from tradecraft.tools.nuclei import Nuclei


class TestNucleiTool:
    @patch("tradecraft.tools.nuclei.nuclei_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawNucleiResult(error="nuclei binary not found")
        tool = Nuclei()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["findings"] == []
        assert res["error"] == "nuclei binary not found"

    @patch("tradecraft.tools.nuclei.nuclei_execute.execute")
    @patch("tradecraft.tools.nuclei.nuclei_parse.parse_nuclei_output")
    def test_run_few_findings(self, mock_parse, mock_exec):
        mock_exec.return_value = RawNucleiResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "findings": [
                {"template_id": "cve-1", "severity": "high", "name": "CVE 1"},
                {"template_id": "cve-2", "severity": "medium", "name": "CVE 2"},
            ],
            "total_findings": 2,
            "worst_severity": "high",
            "severities_count": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
        }
        tool = Nuclei()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["total_findings"] == 2
        assert res["worst_severity"] == "high"
        assert len(res["findings"]) == 2
        assert "omitted_findings" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["total_findings"] == 2

    @patch("tradecraft.tools.nuclei.nuclei_execute.execute")
    @patch("tradecraft.tools.nuclei.nuclei_parse.parse_nuclei_output")
    def test_run_smart_tiered_capping_default_limit_25(self, mock_parse, mock_exec):
        mock_exec.return_value = RawNucleiResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "findings": (
                [{"template_id": f"crit-{i}", "severity": "critical", "name": f"Crit {i}"} for i in range(2)]
                + [{"template_id": f"high-{i}", "severity": "high", "name": f"High {i}"} for i in range(3)]
                + [{"template_id": f"med-{i}", "severity": "medium", "name": f"Med {i}"} for i in range(25)]
            ),
            "total_findings": 30,
            "worst_severity": "critical",
            "severities_count": {"critical": 2, "high": 3, "medium": 25, "low": 0, "info": 0},
        }
        tool = Nuclei()
        res = tool.run(target="https://example.com")
        assert res["total_findings"] == 30
        assert len(res["findings"]) == 25
        assert res["omitted_findings"] == 5
        # Ensure all 2 critical and 3 high findings are present in returned findings
        crit_count = sum(1 for f in res["findings"] if f["severity"] == "critical")
        high_count = sum(1 for f in res["findings"] if f["severity"] == "high")
        assert crit_count == 2
        assert high_count == 3
        assert "all 5 critical/high findings retained" in res["note"]
        # Full evidence contains all 30
        assert len(res["_full_evidence"]["findings"]) == 30

    @patch("tradecraft.tools.nuclei.nuclei_execute.execute")
    @patch("tradecraft.tools.nuclei.nuclei_parse.parse_nuclei_output")
    def test_run_critical_and_high_never_omitted_even_exceeding_limit(self, mock_parse, mock_exec):
        mock_exec.return_value = RawNucleiResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "findings": (
                [{"template_id": f"crit-{i}", "severity": "critical", "name": f"Crit {i}"} for i in range(8)]
                + [{"template_id": f"high-{i}", "severity": "high", "name": f"High {i}"} for i in range(5)]
                + [{"template_id": f"med-{i}", "severity": "medium", "name": f"Med {i}"} for i in range(10)]
            ),
            "total_findings": 23,
            "worst_severity": "critical",
            "severities_count": {"critical": 8, "high": 5, "medium": 10, "low": 0, "info": 0},
        }
        tool = Nuclei()
        # Explicit lower limit of 10
        res = tool.run(target="https://example.com", limit=10)
        assert res["total_findings"] == 23
        # All 13 critical & high findings are preserved despite limit=10
        assert len(res["findings"]) == 13
        assert res["omitted_findings"] == 10
        crit_count = sum(1 for f in res["findings"] if f["severity"] == "critical")
        high_count = sum(1 for f in res["findings"] if f["severity"] == "high")
        assert crit_count == 8
        assert high_count == 5

    @patch("tradecraft.tools.nuclei.nuclei_execute.execute")
    @patch("tradecraft.tools.nuclei.nuclei_parse.parse_nuclei_output")
    def test_run_custom_limit(self, mock_parse, mock_exec):
        mock_exec.return_value = RawNucleiResult(stdout="{}", returncode=0)
        mock_parse.return_value = {
            "findings": [
                {"template_id": f"med-{i}", "severity": "medium", "name": f"Med {i}"}
                for i in range(15)
            ],
            "total_findings": 15,
            "worst_severity": "medium",
            "severities_count": {"critical": 0, "high": 0, "medium": 15, "low": 0, "info": 0},
        }
        tool = Nuclei()
        res = tool.run(target="https://example.com", limit=10)
        assert len(res["findings"]) == 10
        assert res["omitted_findings"] == 5

    def test_extract_evidence(self):
        tool = Nuclei()
        result = {
            "target": "https://example.com:443",
            "total_findings": 1,
            "findings": [{"template_id": "cve-1"}],
            "_full_evidence": {"target": "https://example.com:443", "total_findings": 1},
        }
        ev = tool.extract_evidence({"target": "https://example.com:443"}, result)
        assert ev is not None
        canonical_target, full_data = ev
        assert canonical_target == "example.com"
        assert full_data["total_findings"] == 1
        assert "_full_evidence" not in result

    def test_extract_facts(self):
        tool = Nuclei()
        result = {
            "target": "https://example.com",
            "total_findings": 3,
            "worst_severity": "high",
            "evidence_id": "nuclei:example.com",
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["nuclei_findings_count"] == 3
        assert fact["nuclei_worst_severity"] == "high"
        assert fact["evidence"] == "nuclei:example.com"

    def test_extract_facts_empty_when_no_findings(self):
        tool = Nuclei()
        result = {
            "target": "https://example.com",
            "total_findings": 0,
            "worst_severity": None,
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []
