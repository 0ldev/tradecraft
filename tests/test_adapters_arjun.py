"""Unit tests for arjun adapter (execute and parse)."""
import json
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.arjun.execute import (
    RawArjunResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.arjun.parse import host_port_from_target, parse_arjun_output

REAL_CAPTURED_JSON = """{
    "http://webmail.examplepaint.com.br/": {
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0"
        },
        "method": "GET",
        "params": [
            "_action",
            "token"
        ]
    }
}"""

REAL_CAPTURED_STDOUT = """    _
   /_| _ '
  (  |/ /(//) v2.2.7
      _/      

[*] Scanning 0/1: http://webmail.examplepaint.com.br/
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[+] Extracted 57 parameters from response for testing: refreshing, windowopenerror, agent
[*] Logicforcing the URL endpoint
[✓] parameter detected: _action, based on: param value reflection
[✓] parameter detected: token, based on: http code
[+] Parameters found: _action, token
"""


class TestArjunExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("examplepaint.com.br") == "https://examplepaint.com.br/"
        assert normalize_target_url("http://examplepaint.com.br") == "http://examplepaint.com.br/"
        assert normalize_target_url("examplepaint.com.br:80") == "http://examplepaint.com.br:80/"
        assert normalize_target_url("https://examplepaint.com.br/login.php") == "https://examplepaint.com.br/login.php"
        assert normalize_target_url("https://examplepaint.com.br", path="/admin.php") == "https://examplepaint.com.br/admin.php"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("https://examplepaint.com.br/")
        assert argv == [
            "arjun",
            "-u", "https://examplepaint.com.br/",
            "-m", "GET",
            "-w", "small",
            "-t", "5",
            "-T", "10",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            "https://examplepaint.com.br/api",
            method="POST",
            wordlist="medium",
            json_out_path="/tmp/arjun.json",
            threads=8,
            timeout=15,
        )
        assert argv == [
            "arjun",
            "-u", "https://examplepaint.com.br/api",
            "-m", "POST",
            "-w", "medium",
            "-t", "8",
            "-T", "15",
            "-o", "/tmp/arjun.json",
        ]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.arjun.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("https://examplepaint.com.br")
        assert "arjun binary not found" in (res.error or "")

    @patch("tradecraft.adapters.arjun.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://examplepaint.com.br")
        assert res.error is None
        assert res.returncode == 0
        assert "Parameters found" in res.stdout

    @patch("tradecraft.adapters.arjun.execute.subprocess.run")
    def test_execute_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["arjun"], timeout=60)
        res = execute("https://examplepaint.com.br")
        assert "arjun timed out" in (res.error or "")


class TestArjunParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("examplepaint.com.br") == ("examplepaint.com.br", 80)
        assert host_port_from_target("https://examplepaint.com.br") == ("examplepaint.com.br", 443)
        assert host_port_from_target("http://examplepaint.com.br:8080") == ("examplepaint.com.br", 8080)

    def test_parse_real_captured_json(self):
        parsed = parse_arjun_output(REAL_CAPTURED_JSON, REAL_CAPTURED_STDOUT)
        assert parsed["total_parameters"] == 2
        assert parsed["parameters"] == ["_action", "token"]

    def test_parse_stdout_fallback(self):
        # Empty json_output, must parse from stdout
        parsed = parse_arjun_output("", REAL_CAPTURED_STDOUT)
        assert parsed["total_parameters"] == 2
        assert parsed["parameters"] == ["_action", "token"]

    def test_parse_flat_dict_json(self):
        flat_json = json.dumps({"http://example.com/": ["id", "user", "admin"]})
        parsed = parse_arjun_output(flat_json)
        assert parsed["total_parameters"] == 3
        assert parsed["parameters"] == ["admin", "id", "user"]

    def test_parse_empty_and_noise(self):
        assert parse_arjun_output("") == {"parameters": [], "total_parameters": 0}
        noise = "[-] Skipped due to error\n[*] Scanning...\n"
        assert parse_arjun_output("", noise) == {"parameters": [], "total_parameters": 0}
