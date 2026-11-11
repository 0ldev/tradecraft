"""
Unit tests for cve_intel_enricher adapter (execute, parse) and Tool glue.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cve_intel_enricher.execute import (
    RawCveEntry,
    RawCveIntelResult,
    _check_local_cisa_kev,
    _query_epss_api,
    execute,
    extract_cves,
)
from tradecraft.adapters.cve_intel_enricher.parse import parse_cve_intel
from tradecraft.tools.cve_intel_enricher import CveIntelEnricher
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestCveIntelEnricherExecute:
    def test_extract_cves(self):
        text = "Found cve-2023-48022 and CVE-2024-42271 in logs, also cve-2023-48022 duplicate and not-a-cve."
        cves = extract_cves(text)
        assert cves == ["CVE-2023-48022", "CVE-2024-42271"]
        assert extract_cves("cve-2021-44228, CVE-2024-1709") == ["CVE-2021-44228", "CVE-2024-1709"]
        assert extract_cves("no cves here") == []

    def test_local_cisa_kev_lookup(self, tmp_path, monkeypatch):
        kev_file = tmp_path / "kev.json"
        data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "2021-12-10",
                    "vulnerabilityName": "Apache Log4j RCE",
                    "shortDescription": "Log4Shell vulnerability",
                    "requiredAction": "Apply updates.",
                }
            ]
        }
        kev_file.write_text(json.dumps(data))
        monkeypatch.setenv("CISA_KEV_PATH", str(kev_file))

        matches = _check_local_cisa_kev(["CVE-2021-44228", "CVE-2024-99999"])
        assert "CVE-2021-44228" in matches
        assert matches["CVE-2021-44228"]["in_kev"] is True
        assert matches["CVE-2021-44228"]["kev_vulnerability_name"] == "Apache Log4j RCE"
        assert "CVE-2024-99999" not in matches

    @patch("tradecraft.adapters.cve_intel_enricher.execute.requests.get")
    def test_query_epss_api(self, mock_get):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2023-48022", "epss": "0.89200", "percentile": "0.98500"}
            ],
        }
        mock_get.return_value = mock_resp

        res = _query_epss_api(["CVE-2023-48022"])
        assert "CVE-2023-48022" in res
        assert abs(res["CVE-2023-48022"]["epss"] - 0.892) < 0.001
        assert abs(res["CVE-2023-48022"]["percentile"] - 0.985) < 0.001

    @patch("tradecraft.adapters.cve_intel_enricher.execute.requests.get")
    def test_query_epss_api_network_error(self, mock_get):
        mock_get.side_effect = Exception("DNS lookup failed")
        res = _query_epss_api(["CVE-2023-48022"])
        assert res == {}

    def test_execute_invalid_cve(self):
        res = execute("invalid-string")
        assert res.error is not None
        assert "No valid CVE identifiers" in res.error

    @patch("tradecraft.adapters.cve_intel_enricher.execute._query_epss_api")
    def test_execute_offline_ai_cve(self, mock_epss):
        mock_epss.return_value = {}
        # Ray Jobs unauthenticated code execution in curated AI fallback
        res = execute("CVE-2023-48022")
        assert len(res.entries) == 1
        entry = res.entries[0]
        assert entry.cve == "CVE-2023-48022"
        assert entry.is_ai_stack is True
        assert entry.priority == "HIGH"
        assert entry.epss_score is not None and entry.epss_score >= 0.5

    @patch("tradecraft.adapters.cve_intel_enricher.execute._query_epss_api")
    def test_execute_min_epss_filter(self, mock_epss):
        mock_epss.return_value = {}
        # CVE-2024-42271 has fallback epss ~0.315; filter with min_epss=0.5 should drop it
        res = execute("CVE-2024-42271", min_epss=0.5)
        assert len(res.entries) == 0

        res_pass = execute("CVE-2024-42271", min_epss=0.2)
        assert len(res_pass.entries) == 1


class TestCveIntelEnricherParse:
    def test_parse_cve_intel_sorting_and_counts(self):
        entries = [
            RawCveEntry(cve="CVE-2024-0001", priority="LOW", epss_score=0.01),
            RawCveEntry(cve="CVE-2021-44228", priority="CRITICAL", in_kev=True, epss_score=0.97),
            RawCveEntry(cve="CVE-2023-48022", priority="HIGH", is_ai_stack=True, epss_score=0.89),
        ]
        raw = RawCveIntelResult(
            cves_requested=["CVE-2024-0001", "CVE-2021-44228", "CVE-2023-48022"],
            entries=entries,
            sources={"test": True},
        )
        parsed = parse_cve_intel(raw)
        assert parsed["total_evaluated"] == 3
        assert parsed["critical_count"] == 1
        assert parsed["high_count"] == 1
        assert parsed["kev_count"] == 1
        assert parsed["ai_stack_count"] == 1

        # Ordering should put CRITICAL first, then HIGH, then LOW
        ordered_cves = [e["cve"] for e in parsed["entries"]]
        assert ordered_cves == ["CVE-2021-44228", "CVE-2023-48022", "CVE-2024-0001"]

    def test_parse_cve_intel_error(self):
        raw = RawCveIntelResult(cves_requested=[], error="bad input")
        parsed = parse_cve_intel(raw)
        assert parsed["error"] == "bad input"
        assert parsed["total_evaluated"] == 0


class TestCveIntelEnricherTool:
    def test_registration(self):
        tool = next((t for t in ALL_TOOLS if t.tool_id == "cve_intel_enricher"), None)
        assert tool is not None
        assert isinstance(tool, CveIntelEnricher)

    def test_spec_attributes(self):
        tool = CveIntelEnricher()
        assert tool.spec.name == "cve_intel_enricher"
        assert tool.required_binary is None
        assert tool.scope_param is None
        assert tool.destructive is False
        assert tool.is_available() is True

    @patch("tradecraft.adapters.cve_intel_enricher.execute._query_epss_api")
    def test_tool_run(self, mock_epss):
        mock_epss.return_value = {}
        tool = CveIntelEnricher()
        res = tool.run(cve="CVE-2023-48022, CVE-2024-37032")
        assert res["total_evaluated"] == 2
        assert res["ai_stack_count"] == 2
        assert len(res["entries"]) == 2

        # Evidence extraction
        ev = tool.extract_evidence({"cve": "CVE-2023-48022"}, res)
        assert ev is not None
        assert ev[0] == "CVE-2023-48022"

    def test_profile_membership(self):
        web = load_profile("web")
        assert "cve_intel_enricher" in web
