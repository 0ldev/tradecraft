"""Unit tests for dalfox adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.dalfox.execute import (
    RawDalfoxResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.dalfox.parse import host_port_from_target, parse_dalfox_output

REAL_CAPTURED_VULN_JSON = """{
  "findings": [
    {
      "confidence": "high",
      "confidence_reason": "payload reached an executable position in the parsed response",
      "cwe": "CWE-79",
      "data": "http://127.0.0.1:9876/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx40963f13%3E",
      "detection_method": "reflection",
      "evidence": "DOM verification successful for param q (DOM marker)",
      "inject_type": "inHTML",
      "location": "Query",
      "message_id": 606,
      "message_str": "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx40963f13>",
      "method": "GET",
      "param": "q",
      "payload": "<svg onload=alert(1) class=dlx40963f13>",
      "severity": "High",
      "type": "V",
      "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it"
    }
  ],
  "meta": {
    "dalfox_version": "3.2.4",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 1,
    "incomplete": false,
    "scan_duration_ms": 541,
    "target_summary": [
      {
        "findings_count": 1,
        "status": "findings",
        "target": "http://127.0.0.1:9876/?q=test"
      }
    ],
    "targets": [
      "http://127.0.0.1:9876/?q=test"
    ],
    "targets_deduplicated": 0,
    "total_requests": 32
  }
}"""

REAL_CAPTURED_CLEAN_JSON = """{
  "findings": [],
  "meta": {
    "dalfox_version": "3.2.4",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 0,
    "incomplete": false,
    "scan_duration_ms": 3155,
    "target_summary": [
      {
        "findings_count": 0,
        "status": "clean",
        "target": "https://httpbin.org/get?q=test"
      }
    ],
    "targets": [
      "https://httpbin.org/get?q=test"
    ],
    "targets_deduplicated": 0,
    "total_requests": 25
  }
}"""


class TestDalfoxExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("http://example.com/search?q=1") == "http://example.com/search?q=1"
        assert normalize_target_url("https://example.com/test") == "https://example.com/test"
        assert normalize_target_url("example.com/test?q=1") == "https://example.com/test?q=1"
        assert normalize_target_url("example.com:80/test") == "http://example.com:80/test"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("https://example.com/search?q=1")
        assert argv == [
            "dalfox",
            "scan",
            "https://example.com/search?q=1",
            "-i", "url",
            "-f", "json",
            "--no-color",
            "--timeout", "10",
            "--scan-timeout", "20",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            "https://example.com/submit",
            parameter="comment",
            data="comment=hello&user=test",
            method="POST",
            cookie="session=xyz",
            header="X-Forwarded-For: 127.0.0.1",
            output_file="/tmp/out.json",
            timeout=5,
            scan_timeout=15,
        )
        assert argv == [
            "dalfox",
            "scan",
            "https://example.com/submit",
            "-i", "url",
            "-f", "json",
            "--no-color",
            "-o", "/tmp/out.json",
            "-p", "comment",
            "-d", "comment=hello&user=test",
            "-X", "POST",
            "--cookies", "session=xyz",
            "-H", "X-Forwarded-For: 127.0.0.1",
            "--timeout", "5",
            "--scan-timeout", "15",
        ]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "Target cannot be empty"

    @patch("shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("https://example.com")
        assert "dalfox binary not found on PATH" in (res.error or "")

    @patch("shutil.which", return_value="/usr/local/bin/dalfox")
    @patch("subprocess.run")
    def test_execute_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Results written to /tmp/dalfox_xxx/output.json"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        with patch("builtins.open", MagicMock()) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = REAL_CAPTURED_CLEAN_JSON
            with patch("os.path.exists", return_value=True):
                res = execute("https://example.com/test?q=1")
                assert res.error is None
                assert res.returncode == 0
                assert res.json_content == REAL_CAPTURED_CLEAN_JSON

    @patch("shutil.which", return_value="/usr/local/bin/dalfox")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dalfox", timeout=45))
    def test_execute_timeout(self, mock_run, mock_which):
        res = execute("https://example.com/test?q=1", subprocess_timeout=45)
        assert "timed out after 45s" in (res.error or "")


class TestDalfoxParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com/path?q=1") == ("example.com", 443)
        assert host_port_from_target("http://192.168.1.1:8080/path") == ("192.168.1.1", 8080)
        assert host_port_from_target("sub.example.com") == ("sub.example.com", 80)

    def test_parse_real_captured_vuln_json(self):
        parsed = parse_dalfox_output(json_content=REAL_CAPTURED_VULN_JSON)
        assert parsed["total_findings"] == 1
        assert parsed["vulnerable_count"] == 1
        assert parsed["reflected_count"] == 0
        assert parsed["dom_count"] == 0
        finding = parsed["findings"][0]
        assert finding["param"] == "q"
        assert finding["type"] == "V"
        assert finding["severity"] == "High"
        assert "<svg onload=alert(1)" in finding["payload"]
        assert "http://127.0.0.1:9876/?q=" in finding["poc"]
        assert finding["cwe"] == "CWE-79"

    def test_parse_real_captured_clean_json(self):
        parsed = parse_dalfox_output(json_content=REAL_CAPTURED_CLEAN_JSON)
        assert parsed["total_findings"] == 0
        assert parsed["vulnerable_count"] == 0
        assert parsed["reflected_count"] == 0
        assert parsed["dom_count"] == 0
        assert parsed["findings"] == []
        assert parsed["meta"]["dalfox_version"] == "3.2.4"

    def test_parse_stdout_json_lines_fallback(self):
        stdout = """
[warn] stdin is an open pipe
{"type": "R", "param": "search", "severity": "Medium", "payload": "<test>", "data": "http://example.com/?search=%3Ctest%3E"}
"""
        parsed = parse_dalfox_output(stdout=stdout)
        assert parsed["total_findings"] == 1
        assert parsed["reflected_count"] == 1
        assert parsed["vulnerable_count"] == 0
        assert parsed["findings"][0]["param"] == "search"
        assert parsed["findings"][0]["type"] == "R"

    def test_parse_empty_and_noise(self):
        parsed = parse_dalfox_output(json_content="", stdout="invalid output")
        assert parsed["total_findings"] == 0
        assert parsed["findings"] == []
