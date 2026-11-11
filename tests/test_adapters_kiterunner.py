"""Unit tests for kiterunner adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.kiterunner.execute import (
    RawKiterunnerResult,
    build_argv,
    execute,
    find_kiterunner_binary,
    normalize_target_url,
)
from tradecraft.adapters.kiterunner.parse import (
    host_port_from_target,
    parse_kiterunner_output,
)

REAL_CAPTURED_KITERUNNER_STDOUT = """
{"level":"info","delay":"0s","full-scan":true,"target":"https://httpbin.org","time":"2026-11-01T22:06:12Z","message":"scan options"}
{"method":"POST","target":"https://httpbin.org","path":"/api/v1/hibernate","responses":[{"uri":"","sc":200,"len":173}],"time":"2026-11-01T22:06:18Z"}
{"method":"GET","target":"https://httpbin.org","path":"/api/swagger","responses":[{"uri":"","sc":200,"len":4512}],"time":"2026-11-01T22:06:26Z"}
{"method":"GET","target":"https://httpbin.org","path":"/api/v1/logins","responses":[{"uri":"","sc":401,"len":55}],"time":"2026-11-01T22:06:25Z"}
{"method":"GET","target":"https://httpbin.org","path":"/api/v1/dead","responses":[{"uri":"","sc":404,"len":0}],"time":"2026-11-01T22:06:25Z"}
{"level":"info","results":3,"time":"2026-11-01T22:06:28Z","message":"scan complete"}
"""


class TestKiterunnerExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com/api") == "http://example.com/api"
        assert normalize_target_url("example.com:80") == "http://example.com:80"
        assert normalize_target_url("example.com:443") == "https://example.com:443"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv(
            target_url="https://example.com",
            wordlist_path="/path/to/api-routes.kite",
            max_connections=5,
            binary="kr",
        )
        assert argv == [
            "kr",
            "scan",
            "https://example.com",
            "-w",
            "/path/to/api-routes.kite",
            "--kitebuilder-full-scan",
            "--progress=false",
            "-q",
            "-x",
            "5",
            "-o",
            "json",
        ]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target URL"

    @patch("tradecraft.adapters.kiterunner.execute.find_kiterunner_binary", return_value=None)
    def test_execute_missing_binary(self, mock_bin):
        res = execute("https://example.com")
        assert "kiterunner (kr) binary not found" in (res.error or "")

    @patch("tradecraft.adapters.kiterunner.execute.find_kiterunner_binary", return_value="/usr/bin/kr")
    @patch("tradecraft.adapters.kiterunner.execute.resolve_wordlist", return_value="/nonexistent/missing.kite")
    def test_execute_missing_wordlist(self, mock_res, mock_bin):
        res = execute("https://example.com")
        assert "wordlist not found" in (res.error or "")

    @patch("tradecraft.adapters.kiterunner.execute.find_kiterunner_binary", return_value="/usr/bin/kr")
    @patch("tradecraft.adapters.kiterunner.execute.os.path.isfile", return_value=True)
    @patch("tradecraft.adapters.kiterunner.execute.subprocess.run")
    def test_execute_success(self, mock_run, mock_file, mock_bin):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_KITERUNNER_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://example.com")
        assert res.error is None
        assert res.returncode == 0
        assert "/api/swagger" in res.stdout

    @patch("tradecraft.adapters.kiterunner.execute.find_kiterunner_binary", return_value="/usr/bin/kr")
    @patch("tradecraft.adapters.kiterunner.execute.os.path.isfile", return_value=True)
    @patch("tradecraft.adapters.kiterunner.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_file, mock_bin):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["kr"], timeout=60)
        res = execute("https://example.com", timeout=60)
        assert "kiterunner timed out after 60s" in (res.error or "")


class TestKiterunnerParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://api.example.com") == ("api.example.com", 443)
        assert host_port_from_target("http://api.example.com:8080/v1") == ("api.example.com", 8080)
        assert host_port_from_target("example.com") == ("example.com", 80)

    def test_parse_empty(self):
        parsed = parse_kiterunner_output("", target_url="https://example.com")
        assert parsed["target"] == "https://example.com"
        assert parsed["total_endpoints"] == 0
        assert parsed["endpoints"] == []

    def test_parse_real_captured_stdout(self):
        parsed = parse_kiterunner_output(REAL_CAPTURED_KITERUNNER_STDOUT, target_url="https://httpbin.org")
        assert parsed["target"] == "https://httpbin.org"
        # 404 should be filtered out, leaving 3 endpoints: 200, 200, 401
        assert parsed["total_endpoints"] == 3
        paths = [ep["path"] for ep in parsed["endpoints"]]
        assert "/api/v1/hibernate" in paths
        assert "/api/swagger" in paths
        assert "/api/v1/logins" in paths
        assert "/api/v1/dead" not in paths

        ep_swagger = next(ep for ep in parsed["endpoints"] if ep["path"] == "/api/swagger")
        assert ep_swagger["method"] == "GET"
        assert ep_swagger["status_code"] == 200
        assert ep_swagger["length"] == 4512
