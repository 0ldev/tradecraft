"""Unit tests for sqlmap adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.sqlmap.execute import (
    RawSqlmapResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.sqlmap.parse import host_port_from_target, parse_sqlmap_output

REAL_CAPTURED_CSV = """Target URL,Place,Parameter,Technique(s),Note(s)
http://example.com/vuln.php?id=1,GET,id,boolean-based blind,
"""

REAL_CAPTURED_LOG = """---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 7132=7132
---
[INFO] the back-end DBMS is MySQL
"""

REAL_NEGATIVE_STDOUT = """[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[WARNING] parameter '_action' does not seem to be injectable
[INFO] all tested parameters do not appear to be injectable
"""


class TestSqlmapExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("http://example.com/test?id=1") == "http://example.com/test?id=1"
        assert normalize_target_url("https://example.com/test") == "https://example.com/test"
        assert normalize_target_url("example.com/test?id=1") == "https://example.com/test?id=1"
        assert normalize_target_url("example.com:80/test") == "http://example.com:80/test"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("https://example.com/test?id=1")
        assert argv == [
            "sqlmap",
            "-u", "https://example.com/test?id=1",
            "--batch",
            "--random-agent",
            "--timeout=10",
            "--retries=1",
            "--level=1",
            "--risk=1",
            "--threads=2",
            "--smart",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            "https://example.com/login",
            parameter="user",
            data="user=admin&pass=123",
            method="POST",
            level=3,
            risk=2,
            output_dir="/tmp/sqlmap_out",
            timeout=15,
            threads=4,
            smart=False,
        )
        assert "-p" in argv and argv[argv.index("-p") + 1] == "user"
        assert "--data" in argv and argv[argv.index("--data") + 1] == "user=admin&pass=123"
        assert "--level=3" in argv
        assert "--risk=2" in argv
        assert "--threads=4" in argv
        assert "--output-dir" in argv and argv[argv.index("--output-dir") + 1] == "/tmp/sqlmap_out"
        assert "--smart" not in argv

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.sqlmap.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("https://example.com")
        assert "sqlmap binary not found" in (res.error or "")

    @patch("tradecraft.adapters.sqlmap.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_NEGATIVE_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://example.com/?id=1")
        assert res.error is None
        assert res.returncode == 0
        assert res.duration_seconds >= 0

    @patch("tradecraft.adapters.sqlmap.execute.subprocess.run")
    def test_execute_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sqlmap"], timeout=60)
        res = execute("https://example.com/?id=1")
        assert "sqlmap timed out" in (res.error or "")
        assert res.duration_seconds >= 0


class TestSqlmapParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("http://example.com/item.php?id=1") == ("example.com", 80)
        assert host_port_from_target("https://example.com:8443/item") == ("example.com", 8443)
        assert host_port_from_target("example.com") == ("example.com", 80)

    def test_parse_vulnerable_output(self):
        parsed = parse_sqlmap_output(
            csv_content=REAL_CAPTURED_CSV,
            log_content=REAL_CAPTURED_LOG,
            stdout="[INFO] the back-end DBMS is MySQL\nsqlmap identified the following injection points",
        )
        assert parsed["injectable"] is True
        assert parsed["dbms"] == "MySQL"
        assert parsed["total_vulnerabilities"] == 1
        vuln = parsed["vulnerabilities"][0]
        assert vuln["parameter"] == "id"
        assert vuln["place"] == "GET"
        assert "boolean-based blind" in vuln["techniques"]
        assert "AND boolean-based blind" in vuln["title"]
        assert "id=1 AND 7132=7132" in vuln["payload"]

    def test_parse_negative_output(self):
        parsed = parse_sqlmap_output(
            csv_content="",
            log_content="",
            stdout=REAL_NEGATIVE_STDOUT,
        )
        assert parsed["injectable"] is False
        assert parsed["dbms"] is None
        assert parsed["total_vulnerabilities"] == 0
        assert parsed["vulnerabilities"] == []
