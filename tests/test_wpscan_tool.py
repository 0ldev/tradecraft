"""Unit tests for WPScan Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.wpscan.execute import RawWPScanResult
from tradecraft.tools.wpscan import WPScan


class TestWPScanTool:
    @patch("tradecraft.tools.wpscan.wpscan_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawWPScanResult(error="wpscan binary not found")
        tool = WPScan()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["is_wordpress"] is False
        assert res["plugins"] == []
        assert res["vulnerabilities"] == []
        assert res["error"] == "wpscan binary not found"

    @patch("tradecraft.tools.wpscan.wpscan_execute.execute")
    @patch("tradecraft.tools.wpscan.wpscan_parse.parse_wpscan_output")
    def test_run_success(self, mock_parse, mock_exec):
        mock_exec.return_value = RawWPScanResult(returncode=5, target_url="https://example.com/")
        mock_parse.return_value = {
            "is_wordpress": True,
            "version": {"number": "4.9.9", "status": "outdated"},
            "theme": {"slug": "twentynineteen", "version": "1.0"},
            "users": ["admin"],
            "plugins": [{"slug": "contact-form-7", "version": "5.0.3"}],
            "vulnerabilities": [{"type": "core", "title": "WP Traversal"}],
            "total_plugins": 1,
            "total_vulnerabilities": 1,
            "interesting_findings": [],
        }
        tool = WPScan()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["is_wordpress"] is True
        assert res["version"]["number"] == "4.9.9"
        assert res["total_plugins"] == 1
        assert res["total_vulnerabilities"] == 1
        assert "omitted_plugins" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["is_wordpress"] is True

    @patch("tradecraft.tools.wpscan.wpscan_execute.execute")
    @patch("tradecraft.tools.wpscan.wpscan_parse.parse_wpscan_output")
    def test_run_flags_vulnerability_lookup_skipped_without_token(self, mock_parse, mock_exec):
        # When wpscan runs with no WPSCAN_API_TOKEN configured, vp/vt
        # enumeration is dropped and total_vulnerabilities comes back 0
        # for every plugin -- which looks identical to "checked, found
        # none." vulnerability_lookup must say the lookup was skipped.
        import os

        os.environ.pop("WPSCAN_API_TOKEN", None)
        mock_exec.return_value = RawWPScanResult(returncode=0, target_url="https://example.com/")
        mock_parse.return_value = {
            "is_wordpress": True,
            "version": {"number": "7.1.4", "status": "latest"},
            "theme": {"slug": "hello-elementor", "version": "3.4.4"},
            "users": [],
            "plugins": [{"slug": "elementor", "version": "3.32.5", "vulnerabilities_count": 0}],
            "vulnerabilities": [],
            "total_plugins": 1,
            "total_vulnerabilities": 0,
            "interesting_findings": [],
        }
        tool = WPScan()
        res = tool.run(target="https://example.com", api_token="")
        assert res["vulnerability_lookup"] == (
            "skipped: no WPSCAN_API_TOKEN configured -- total_vulnerabilities does not reflect a real check"
        )

    @patch("tradecraft.tools.wpscan.wpscan_execute.execute")
    @patch("tradecraft.tools.wpscan.wpscan_parse.parse_wpscan_output")
    def test_run_flags_vulnerability_lookup_performed_with_token(self, mock_parse, mock_exec):
        mock_exec.return_value = RawWPScanResult(returncode=5, target_url="https://example.com/")
        mock_parse.return_value = {
            "is_wordpress": True,
            "version": {"number": "4.9.9"},
            "theme": None,
            "users": [],
            "plugins": [],
            "vulnerabilities": [{"type": "core", "title": "WP Traversal"}],
            "total_plugins": 0,
            "total_vulnerabilities": 1,
            "interesting_findings": [],
        }
        tool = WPScan()
        res = tool.run(target="https://example.com", api_token="real_token")
        assert res["vulnerability_lookup"] == "performed"

    @patch("tradecraft.tools.wpscan.wpscan_execute.execute")
    @patch("tradecraft.tools.wpscan.wpscan_parse.parse_wpscan_output")
    def test_run_omits_items_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawWPScanResult(returncode=5)
        mock_parse.return_value = {
            "is_wordpress": True,
            "version": {"number": "5.0"},
            "theme": None,
            "users": [],
            "plugins": [{"slug": f"plugin_{i}", "version": "1.0"} for i in range(15)],
            "vulnerabilities": [{"type": "plugin", "title": f"Vuln {i}"} for i in range(15)],
            "total_plugins": 15,
            "total_vulnerabilities": 15,
            "interesting_findings": [],
        }
        tool = WPScan()
        res = tool.run(target="https://example.com")
        assert res["total_plugins"] == 15
        assert len(res["plugins"]) == 10
        assert res["omitted_plugins"] == 5
        assert len(res["vulnerabilities"]) == 10
        assert res["omitted_vulnerabilities"] == 5
        assert len(res["_full_evidence"]["plugins"]) == 15

    def test_extract_evidence(self):
        tool = WPScan()
        result = {
            "target": "https://example.com/blog",
            "plugins": [{"slug": "jetpack"}],
            "_full_evidence": {"raw": "data"},
        }
        extracted = tool.extract_evidence({"target": "https://example.com/blog"}, result)
        assert extracted is not None
        canonical, full = extracted
        assert canonical == "example.com"
        assert full == {"raw": "data"}
        assert "_full_evidence" not in result

    def test_extract_evidence_empty(self):
        tool = WPScan()
        assert tool.extract_evidence({}, {}) is None

    def test_extract_facts(self):
        tool = WPScan()
        result = {
            "target": "https://example.com",
            "is_wordpress": True,
            "version": {"number": "4.9.9"},
            "total_plugins": 5,
            "total_vulnerabilities": 3,
            "evidence_id": "ev_wp_123",
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["is_wordpress"] is True
        assert fact["wordpress_version"] == "4.9.9"
        assert fact["wordpress_plugins"] == 5
        assert fact["wordpress_vulnerabilities"] == 3
        assert fact["evidence"] == "ev_wp_123"

    def test_extract_facts_not_wordpress(self):
        tool = WPScan()
        result = {
            "target": "https://example.com",
            "is_wordpress": False,
            "total_plugins": 0,
            "total_vulnerabilities": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com"}, result)
        assert facts == []
