"""Unit tests for subzy adapter (execute and parse)."""
from unittest.mock import MagicMock, patch

from tradecraft.adapters.subzy.execute import (
    RawSubzyResult,
    build_argv,
    execute,
    normalize_targets,
)
from tradecraft.adapters.subzy.parse import parse_subzy_output


class TestSubzyExecute:
    def test_normalize_targets(self):
        assert normalize_targets("example.com") == ["example.com"]
        assert normalize_targets("https://sub.example.com/page") == ["sub.example.com"]
        assert normalize_targets("sub1.example.com, sub2.example.com") == [
            "sub1.example.com",
            "sub2.example.com",
        ]
        assert normalize_targets("") == []

    def test_build_argv(self):
        cmd = build_argv("/tmp/targets.txt", concurrency=15)
        assert cmd == [
            "subzy",
            "run",
            "--targets", "/tmp/targets.txt",
            "--hide_fails",
            "--concurrency", "15",
        ]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "Missing or invalid takeover target(s)"

    @patch("tradecraft.adapters.subzy.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "[ VULNERABLE ]  -  sub.example.com  [ S3 ]\n"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("sub.example.com")
        assert res.error is None
        assert "sub.example.com" in res.stdout

    @patch("tradecraft.adapters.subzy.execute.subprocess.run", side_effect=FileNotFoundError)
    def test_execute_missing_binary(self, mock_run):
        res = execute("example.com")
        assert res.error == "subzy executable not found"


class TestSubzyParse:
    def test_parse_real_captured_vulnerable_block(self):
        stdout = (
            "-----------------\n"
            "[ VULNERABLE ]  -  materiais.examplepaint.com.br  [ Uptimerobot ]\n"
            "[ DISCUSSION ]  -  [Issue #45](https://github.com/EdOverflow/can-i-take-over-xyz/issues/45)\n"
            "[ DOCUMENTATION ]  -  [Uptimerobot-Sub-takeover](https://exploit.linuxsec.org/uptimerobot-com-custom-domain-subdomain-takeover/)\n"
            "-----------------\n"
        )
        findings = parse_subzy_output(stdout)
        assert len(findings) == 1
        f = findings[0]
        assert f["subdomain"] == "materiais.examplepaint.com.br"
        assert f["service"] == "Uptimerobot"
        assert f["status"] == "vulnerable"
        assert "exploit.linuxsec.org" in f["documentation"]
        assert "Issue #45" in f["discussion"]

    def test_not_vulnerable_lines_never_matched(self):
        stdout = (
            "[ NOT VULNERABLE ]  -  examplepaint.com.br\n"
            "[ NOT VULNERABLE ]  -  admin.examplepaint.com.br\n"
        )
        findings = parse_subzy_output(stdout)
        assert findings == []

    def test_empty_and_noise_output(self):
        assert parse_subzy_output("") == []
        assert parse_subzy_output("[ * ] Loaded 5 targets\n[ * ] Concurrent requests: 10\n") == []
