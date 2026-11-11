"""Unit tests for wpscan adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.wpscan.execute import (
    RawWPScanResult,
    build_argv,
    execute,
    has_vulnerability_api_token,
    normalize_target_url,
)
from tradecraft.adapters.wpscan.parse import host_port_from_target, parse_wpscan_output

SAMPLE_WPSCAN_JSON = """{
  "banner": {
    "version": "3.8.28"
  },
  "target_url": "https://example.com/",
  "version": {
    "number": "4.9.9",
    "status": "outdated",
    "vulnerabilities": [
      {
        "title": "WordPress 4.9-4.9.9 - Authenticated Path Traversal",
        "fixed_in": "4.9.10",
        "references": {
          "cve": ["2019-8942"]
        }
      }
    ]
  },
  "main_theme": {
    "slug": "twentynineteen",
    "version": {
      "number": "1.0"
    },
    "vulnerabilities": []
  },
  "plugins": {
    "contact-form-7": {
      "slug": "contact-form-7",
      "version": {
        "number": "5.0.3"
      },
      "vulnerabilities": [
        {
          "title": "Contact Form 7 <= 5.0.3 - File Upload Vulnerability",
          "fixed_in": "5.0.4",
          "references": {
            "cve": ["2018-12345"]
          }
        }
      ]
    }
  },
  "users": {
    "admin": {
      "id": 1
    },
    "editor": {
      "id": 2
    }
  },
  "interesting_findings": [
    {
      "url": "https://example.com/xmlrpc.php",
      "to_s": "XML-RPC server seems to be enabled: https://example.com/xmlrpc.php",
      "type": "xmlrpc"
    }
  ]
}"""


class TestWPScanExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com/"
        assert normalize_target_url("http://example.com:8080") == "http://example.com:8080/"
        # http on default port upgrades to https
        assert normalize_target_url("http://example.com") == "https://example.com/"
        assert normalize_target_url("https://example.com/blog") == "https://example.com/blog/"
        assert normalize_target_url("") == ""

    def test_build_argv_no_token_drops_vp_vt(self):
        # Without an API token, vp and vt must be dropped to prevent scan abort
        argv = build_argv("https://example.com/", enumerate="u,vp,vt", api_token="")
        assert "--enumerate" in argv
        idx = argv.index("--enumerate")
        assert argv[idx + 1] == "u"

    def test_build_argv_with_token_retains_vp_vt(self):
        argv = build_argv("https://example.com/", enumerate="u,vp,vt", api_token="secret_token")
        assert "--enumerate" in argv
        idx = argv.index("--enumerate")
        assert argv[idx + 1] == "u,vp,vt"
        assert "--api-token" in argv
        assert argv[argv.index("--api-token") + 1] == "secret_token"

    def test_has_vulnerability_api_token(self):
        import os

        assert has_vulnerability_api_token("secret") is True
        assert has_vulnerability_api_token("") is False
        os.environ.pop("WPSCAN_API_TOKEN", None)
        assert has_vulnerability_api_token("") is False
        os.environ["WPSCAN_API_TOKEN"] = "env_secret"
        try:
            assert has_vulnerability_api_token("") is True
        finally:
            del os.environ["WPSCAN_API_TOKEN"]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "Target cannot be empty"

    @patch("shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("https://example.com")
        assert "wpscan binary not found on PATH" in (res.error or "")

    @patch("shutil.which", return_value="/usr/local/bin/wpscan")
    @patch("subprocess.run")
    def test_execute_success_exit_codes(self, mock_run, mock_which):
        # Exit code 5 (vulnerabilities found) is a valid success in WPScan
        mock_proc = MagicMock()
        mock_proc.returncode = 5
        mock_proc.stdout = SAMPLE_WPSCAN_JSON
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = execute("https://example.com")
        assert res.error is None
        assert res.returncode == 5
        assert res.stdout == SAMPLE_WPSCAN_JSON

    @patch("shutil.which", return_value="/usr/local/bin/wpscan")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="wpscan", timeout=180))
    def test_execute_timeout(self, mock_run, mock_which):
        res = execute("https://example.com", subprocess_timeout=180)
        assert "timed out after 180s" in (res.error or "")


class TestWPScanParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com/blog/") == ("example.com", 443)
        assert host_port_from_target("http://192.168.1.1:8080") == ("192.168.1.1", 8080)

    def test_parse_sample_wpscan_json(self):
        parsed = parse_wpscan_output(SAMPLE_WPSCAN_JSON)
        assert parsed["is_wordpress"] is True
        assert parsed["version"]["number"] == "4.9.9"
        assert parsed["version"]["status"] == "outdated"
        assert parsed["theme"]["slug"] == "twentynineteen"
        assert parsed["theme"]["version"] == "1.0"
        assert parsed["total_plugins"] == 1
        assert parsed["plugins"][0]["slug"] == "contact-form-7"
        assert parsed["plugins"][0]["version"] == "5.0.3"
        assert parsed["users"] == ["admin", "editor"]
        assert parsed["total_users"] == 2
        assert parsed["total_vulnerabilities"] == 2
        assert len(parsed["interesting_findings"]) == 1
        assert "xmlrpc.php" in parsed["interesting_findings"][0]["url"]

    def test_parse_scan_aborted(self):
        aborted_json = '{"scan_aborted": "The target is down."}'
        parsed = parse_wpscan_output(aborted_json)
        assert parsed["is_wordpress"] is False
        assert "The target is down." in (parsed.get("error") or "")

    def test_parse_empty_and_noise(self):
        parsed = parse_wpscan_output("")
        assert parsed["is_wordpress"] is False
        assert parsed["vulnerabilities"] == []
