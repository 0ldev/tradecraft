"""Unit tests for commix adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.commix.execute import (
    RawCommixResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.commix.parse import (
    host_port_from_target,
    parse_commix_output,
)

REAL_CAPTURED_CLEAN_STDOUT = """
Automated All-in-One OS Command Injection Exploitation Tool
v4.2.dev280

[21:09:36] [info] Testing the results-based classic command injection technique, please wait......... (done)
[21:09:36] [info] Testing the boolean-based blind command injection technique, please wait... (done)
[21:09:36] [info] Testing the time-based blind command injection technique, please wait......... (done)
[21:09:38] [warning] GET parameter 'id' does not seem to be injectable.
[21:09:38] [critical] All tested parameters do not appear to be injectable.
"""

REAL_CAPTURED_VULN_STDOUT = """
Automated All-in-One OS Command Injection Exploitation Tool
v4.2.dev280

[21:10:52] [info] GET parameter 'cmd' appears to be injectable via time-based blind command injection technique.
GET parameter 'cmd' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
Identified the following injection point(s) with a total of 205 HTTP(S) requests:
Parameter: cmd (GET)
 * Technique: Results-based
 * Type: Classic command injection
 * Payload: test;echo OBNXVW$((30+76))$(echo OBNXVW)OBNXVW;

 * Technique: Boolean-based
 * Type: Blind command injection
 * Payload: test;NIP="$(echo KQPFXY)";if [ ${#NIP} -eq 6 ];then echo BOVSLF;fi;
Target OS: Unix
"""

REAL_CAPTURED_VULN_LOGS = """
Target: http://127.0.0.1:18890/?cmd=test (GET)
Command: /bin/commix '--url=http://127.0.0.1:18890/?cmd=test' --batch -p cmd --level=1 --timeout=5 --retries=0 --output-dir=/tmp/commix_vuln_out
Started: 2026-11-01 21:10:40

commix identified the following injection point(s):
Parameter: cmd (GET)
 * Technique: Results-based
 * Type: Classic command injection
 * Boundary: ';' separator, ' ' whitespace
 * Payload: test;echo OBNXVW$((30+76))$(echo OBNXVW)OBNXVW;
 * Reproduce: curl -i -s --get -H 'User-Agent: commix/v4.2.dev280' 'http://127.0.0.1:18890/'

 * Technique: Boolean-based
 * Type: Blind command injection
 * Boundary: ';' separator, ' ' whitespace
 * Payload: test;NIP="$(echo KQPFXY)";if [ ${#NIP} -eq 6 ];then echo BOVSLF;fi;
 * Reproduce: curl -i -s --get -H 'User-Agent: commix/v4.2.dev280' 'http://127.0.0.1:18890/'

Finished: 2026-11-01 21:10:55   Requests: 207   Target OS: Unix
"""


class TestCommixExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com/test") == "http://example.com/test"
        assert normalize_target_url("https://example.com/api") == "https://example.com/api"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("http://example.com/search?q=1")
        assert argv == [
            "commix",
            "--url=http://example.com/search?q=1",
            "--batch",
            "--level=1",
            "--timeout=30",
            "--retries=0",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            target_url="https://example.com/login",
            parameter="user",
            data="user=admin&pass=123",
            method="POST",
            level=3,
            timeout=45,
            output_dir="/tmp/custom_dir",
        )
        assert "-p=user" in argv
        assert "--data=user=admin&pass=123" in argv
        assert "--level=3" in argv
        assert "--timeout=45" in argv
        assert "--output-dir=/tmp/custom_dir" in argv

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target URL"

    @patch("tradecraft.adapters.commix.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("http://example.com/test")
        assert "commix binary not found" in (res.error or "")

    @patch("tradecraft.adapters.commix.execute.shutil.which", return_value="/usr/bin/commix")
    @patch("tradecraft.adapters.commix.execute.subprocess.run")
    def test_execute_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_CLEAN_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("http://example.com/search?id=1", parameter="id")
        assert res.error is None
        assert res.returncode == 0
        assert "All tested parameters" in res.stdout

    @patch("tradecraft.adapters.commix.execute.shutil.which", return_value="/usr/bin/commix")
    @patch("tradecraft.adapters.commix.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_which):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["commix"], timeout=50)
        res = execute("http://example.com/search?id=1", timeout=30)
        assert "commix timed out after 50s" in (res.error or "")


class TestCommixParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("http://example.com/test") == ("example.com", 80)
        assert host_port_from_target("https://example.com:8443/api") == ("example.com", 8443)
        assert host_port_from_target("example.com") == ("example.com", 80)

    def test_parse_real_captured_clean_output(self):
        parsed = parse_commix_output(
            stdout=REAL_CAPTURED_CLEAN_STDOUT,
            logs_content="",
            target_url="http://127.0.0.1:18888/?id=1",
            tested_param="id",
        )
        assert parsed["target"] == "http://127.0.0.1:18888/?id=1"
        assert parsed["parameter"] == "id"
        assert parsed["vulnerable"] is False
        assert parsed["total_injections"] == 0
        assert parsed["injections"] == []

    def test_parse_real_captured_vulnerable_logs(self):
        parsed = parse_commix_output(
            stdout=REAL_CAPTURED_VULN_STDOUT,
            logs_content=REAL_CAPTURED_VULN_LOGS,
            target_url="http://127.0.0.1:18890/?cmd=test",
            tested_param="cmd",
        )
        assert parsed["vulnerable"] is True
        assert parsed["total_injections"] == 2
        assert parsed["parameter"] == "cmd"
        assert parsed["target_os"] == "Unix"

        inj1 = parsed["injections"][0]
        assert inj1["technique"] == "Results-based"
        assert inj1["type"] == "Classic command injection"
        assert "echo OBNXVW" in inj1["payload"]
        assert "curl" in inj1["reproduce"]

        inj2 = parsed["injections"][1]
        assert inj2["technique"] == "Boolean-based"
        assert inj2["type"] == "Blind command injection"

    def test_parse_stdout_only_fallback(self):
        parsed = parse_commix_output(
            stdout="[+] The parameter 'q' seems to be injectable via time-based technique. Payload: q;sleep 5",
            logs_content="",
            target_url="http://target/vuln",
            tested_param="q",
        )
        assert parsed["vulnerable"] is True
        assert parsed["total_injections"] == 1
        assert parsed["injections"][0]["payload"] == "q;sleep 5"
