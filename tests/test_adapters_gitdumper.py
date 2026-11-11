"""Unit tests for gitdumper adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.gitdumper.execute import (
    RawGitDumperResult,
    build_argv,
    execute,
    find_git_dumper_binary,
    normalize_target_url,
)
from tradecraft.adapters.gitdumper.parse import (
    host_port_from_target,
    parse_gitdumper_output,
)

REAL_CAPTURED_404_STDOUT = """
[-] Testing https://example.com/.git/HEAD [404]
[-] https://example.com//.git/HEAD responded with status code 404
"""

REAL_CAPTURED_SUCCESS_STDOUT = """
[-] Testing http://127.0.0.1:19999/.git/HEAD [200]
[-] Testing http://127.0.0.1:19999/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://127.0.0.1:19999/.git/config [200]
[-] Fetching http://127.0.0.1:19999/.git/HEAD [200]
[-] Fetching http://127.0.0.1:19999/.git/objects/0b/f833504f901e29d0d1dcc0d5708e048627b8b8 [200]
[-] Sanitizing .git/config
[-] Running git checkout .
"""


class TestGitDumperExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com") == "http://example.com"
        assert normalize_target_url("example.com:80") == "http://example.com:80"
        assert normalize_target_url("example.com:443") == "https://example.com:443"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv(
            target_url="https://example.com",
            output_dir="/tmp/dump",
            jobs=5,
            retry=2,
            binary="git-dumper",
        )
        assert argv == ["git-dumper", "-j", "5", "-r", "2", "https://example.com", "/tmp/dump"]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target URL"

    @patch("tradecraft.adapters.gitdumper.execute.find_git_dumper_binary", return_value=None)
    def test_execute_missing_binary(self, mock_bin):
        res = execute("https://example.com")
        assert "git-dumper binary not found" in (res.error or "")

    @patch("tradecraft.adapters.gitdumper.execute.find_git_dumper_binary", return_value="/usr/bin/git-dumper")
    @patch("tradecraft.adapters.gitdumper.execute.subprocess.run")
    def test_execute_404(self, mock_run, mock_bin):
        mock_proc = MagicMock()
        mock_proc.stdout = REAL_CAPTURED_404_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        res = execute("https://example.com")
        assert res.returncode == 1
        assert res.recovered_files == []
        assert res.git_commits == []

    @patch("tradecraft.adapters.gitdumper.execute.find_git_dumper_binary", return_value="/usr/bin/git-dumper")
    @patch("tradecraft.adapters.gitdumper.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_bin):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["git-dumper"], timeout=60)
        res = execute("https://example.com", timeout=60)
        assert "git-dumper timed out after 60s" in (res.error or "")


class TestGitDumperParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com:8443") == ("example.com", 8443)
        assert host_port_from_target("http://example.com") == ("example.com", 80)
        assert host_port_from_target("example.com") == ("example.com", 80)

    def test_parse_404(self):
        parsed = parse_gitdumper_output(
            stdout=REAL_CAPTURED_404_STDOUT,
            stderr="",
            recovered_files=[],
            git_commits=[],
            target_url="https://example.com",
        )
        assert parsed["target"] == "https://example.com"
        assert parsed["git_exposed"] is False
        assert parsed["total_files_recovered"] == 0
        assert parsed["files"] == []
        assert parsed["recent_commits"] == []

    def test_parse_success(self):
        parsed = parse_gitdumper_output(
            stdout=REAL_CAPTURED_SUCCESS_STDOUT,
            stderr="Updated 1 path from the index",
            recovered_files=["secret.txt", "config/db.php"],
            git_commits=["0bf8335 - Alice: initial commit"],
            target_url="http://127.0.0.1:19999",
        )
        assert parsed["target"] == "http://127.0.0.1:19999"
        assert parsed["git_exposed"] is True
        assert parsed["total_files_recovered"] == 2
        assert "secret.txt" in parsed["files"]
        assert len(parsed["recent_commits"]) == 1
        assert "initial commit" in parsed["recent_commits"][0]
