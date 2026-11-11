"""Unit tests for TruffleHog Tool glue, evidence extraction, and facts extraction."""
from unittest.mock import patch

from tradecraft.adapters.trufflehog.execute import RawTruffleHogResult
from tradecraft.tools.trufflehog import TruffleHog


class TestTruffleHogTool:
    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    def test_run_error(self, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(error="trufflehog binary not found")
        tool = TruffleHog()
        res = tool.run(target="https://example.com/app.js")
        assert res["target"] == "https://example.com/app.js"
        assert res["secrets"] == []
        assert res["total_secrets"] == 0
        assert res["verified_count"] == 0
        assert res["error"] == "trufflehog binary not found"

    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    @patch("tradecraft.tools.trufflehog.trufflehog_parse.parse_trufflehog_output")
    def test_run_success(self, mock_parse, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(returncode=0, scanned_urls=["https://example.com/app.js"])
        mock_parse.return_value = {
            "secrets": [
                {
                    "detector": "AWS",
                    "description": "AWS Secret Access Key",
                    "file": "/tmp/trufflehog_xxx/0_app.js",
                    "line": 42,
                    "verified": True,
                    "masked_secret": "AKIA12...7890",
                    "raw_secret": "AKIA12345678901234567890",
                    "decoder": "PLAIN",
                }
            ],
            "total_secrets": 1,
            "verified_count": 1,
            "unverified_count": 0,
            "by_detector": {"AWS": 1},
        }
        tool = TruffleHog()
        res = tool.run(target="https://example.com/app.js")
        assert res["target"] == "https://example.com/app.js"
        assert res["total_secrets"] == 1
        assert res["verified_count"] == 1
        assert len(res["secrets"]) == 1
        assert res["secrets"][0]["secret"] == "AKIA12...7890"
        assert "omitted_secrets" not in res
        assert "_full_evidence" in res
        assert res["_full_evidence"]["verified_count"] == 1

    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    @patch("tradecraft.tools.trufflehog.trufflehog_parse.parse_trufflehog_output")
    def test_run_git_history_mode(self, mock_parse, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(returncode=0)
        mock_parse.return_value = {
            "secrets": [],
            "total_secrets": 0,
            "verified_count": 0,
            "unverified_count": 0,
            "by_detector": {},
        }
        tool = TruffleHog()
        res = tool.run(target="https://github.com/example/repo", scan_git_history=True, verify=True)
        assert res["target"] == "https://github.com/example/repo"
        mock_exec.assert_called_once_with(
            target="https://github.com/example/repo",
            urls="",
            verify=True,
            scan_git_history=True,
        )

    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    @patch("tradecraft.tools.trufflehog.trufflehog_parse.parse_trufflehog_output")
    def test_run_omits_secrets_when_exceeding_limits(self, mock_parse, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(returncode=0)
        mock_parse.return_value = {
            "secrets": [
                {
                    "detector": f"Detector_{i}",
                    "description": "Desc",
                    "file": "app.js",
                    "line": i,
                    "verified": False,
                    "masked_secret": f"tok_{i}...",
                    "raw_secret": f"secret_{i}",
                    "decoder": "PLAIN",
                }
                for i in range(15)
            ],
            "total_secrets": 15,
            "verified_count": 0,
            "unverified_count": 15,
            "by_detector": {"Generic": 15},
        }
        tool = TruffleHog()
        res = tool.run(target="https://example.com/app.js")
        assert res["total_secrets"] == 15
        assert len(res["secrets"]) == 10
        assert res["omitted_secrets"] == 5
        assert "5 more secrets omitted" in res["note"]
        assert len(res["_full_evidence"]["secrets"]) == 15

    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    @patch("tradecraft.tools.trufflehog.trufflehog_parse.parse_trufflehog_output")
    def test_run_surfaces_aspnet_machinekey_unmasked(self, mock_parse, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(returncode=0)
        mock_parse.return_value = {
            "secrets": [],
            "total_secrets": 4,
            "verified_count": 0,
            "unverified_count": 4,
            "by_detector": {"ASPNETValidationKey": 1},
            "aspnet_machinekey": {
                "validation_key": "A1B2" * 20,
                "decryption_key": "FEDC" * 12,
                "validation_algorithm": "HMACSHA256",
                "decryption_algorithm": "AES",
                "file": "web.config",
            },
        }
        tool = TruffleHog()
        res = tool.run(target="https://example.com")
        assert res["aspnet_machinekey"]["validation_key"] == "A1B2" * 20
        assert res["aspnet_machinekey"]["decryption_algorithm"] == "AES"

    @patch("tradecraft.tools.trufflehog.trufflehog_execute.execute")
    @patch("tradecraft.tools.trufflehog.trufflehog_parse.parse_trufflehog_output")
    def test_run_omits_aspnet_machinekey_key_when_absent(self, mock_parse, mock_exec):
        mock_exec.return_value = RawTruffleHogResult(returncode=0)
        mock_parse.return_value = {
            "secrets": [],
            "total_secrets": 0,
            "verified_count": 0,
            "unverified_count": 0,
            "by_detector": {},
            "aspnet_machinekey": None,
        }
        tool = TruffleHog()
        res = tool.run(target="https://example.com")
        assert "aspnet_machinekey" not in res

    def test_extract_evidence(self):
        tool = TruffleHog()
        result = {
            "target": "https://example.com/bundle.js",
            "secrets": [{"detector": "AWS"}],
            "_full_evidence": {"raw": "data"},
        }
        extracted = tool.extract_evidence({"target": "https://example.com/bundle.js"}, result)
        assert extracted is not None
        canonical, full = extracted
        assert canonical == "example.com"
        assert full == {"raw": "data"}
        assert "_full_evidence" not in result

    def test_extract_evidence_empty(self):
        tool = TruffleHog()
        assert tool.extract_evidence({}, {}) is None

    def test_extract_facts_secrets_detected(self):
        tool = TruffleHog()
        result = {
            "target": "https://example.com/bundle.js",
            "total_secrets": 2,
            "verified_count": 1,
            "evidence_id": "ev_th_123",
        }
        facts = tool.extract_facts({"target": "https://example.com/bundle.js"}, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com"
        assert fact["port"] == 443
        assert fact["secrets_detected"] == 2
        assert fact["secrets_verified"] == 1
        assert fact["evidence"] == "ev_th_123"

    def test_extract_facts_empty_when_no_secrets(self):
        tool = TruffleHog()
        result = {
            "target": "https://example.com/bundle.js",
            "total_secrets": 0,
            "verified_count": 0,
        }
        facts = tool.extract_facts({"target": "https://example.com/bundle.js"}, result)
        assert facts == []
