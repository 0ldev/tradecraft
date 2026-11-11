"""Unit tests for dnsx adapter (execute and parse)."""
import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.dnsx.execute import (
    RawDnsxResult,
    build_argv,
    execute,
    normalize_targets,
)
from tradecraft.adapters.dnsx.parse import parse_dns_records


class TestDnsxExecute:
    def test_normalize_targets(self):
        assert normalize_targets("example.com") == ["example.com"]
        assert normalize_targets("https://example.com/some/path") == ["example.com"]
        assert normalize_targets("example.com:8443") == ["example.com"]
        assert normalize_targets("sub1.example.com, sub2.example.com, sub1.example.com") == [
            "sub1.example.com",
            "sub2.example.com",
        ]
        assert normalize_targets("") == []

    def test_build_argv_recon(self):
        cmd = build_argv("/tmp/hosts.txt", query_type="recon")
        assert cmd == [
            "dnsx",
            "-l", "/tmp/hosts.txt",
            "-silent",
            "-j",
            "-omit-raw",
            "-cdn",
            "-asn",
            "-recon",
        ]

    def test_build_argv_single_record(self):
        cmd = build_argv("/tmp/hosts.txt", query_type="mx")
        assert cmd == [
            "dnsx",
            "-l", "/tmp/hosts.txt",
            "-silent",
            "-j",
            "-omit-raw",
            "-cdn",
            "-asn",
            "-mx",
        ]

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "Missing or invalid DNS target(s)"

    @patch("tradecraft.adapters.dnsx.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = '{"host":"example.com","a":["93.184.216.34"],"status_code":"NOERROR"}\n'
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("example.com")
        assert res.error is None
        assert "93.184.216.34" in res.stdout

    @patch("tradecraft.adapters.dnsx.execute.subprocess.run", side_effect=FileNotFoundError)
    def test_execute_missing_binary(self, mock_run):
        res = execute("example.com")
        assert res.error == "dnsx executable not found"


class TestDnsxParse:
    def test_parse_real_captured_output(self):
        stdout = (
            '{"host":"examplepaint.com.br","ttl":2021,'
            '"a":["192.0.2.10"],'
            '"mx":["mx.core.examplehost.net","mx.a.examplehost.net"],'
            '"ns":["ns1.examplehost.net","ns2.examplehost.net"],'
            '"txt":["v=spf1 ip4:192.0.2.10 +a +mx include:_spf.examplehost.net -all"],'
            '"status_code":"NOERROR"}\n'
            '{"host":"nonexistent.examplepaint.com.br","status_code":"NXDOMAIN"}\n'
        )

        records = parse_dns_records(stdout)
        assert len(records) == 2

        r1 = records[0]
        assert r1["host"] == "examplepaint.com.br"
        assert r1["resolves"] is True
        assert r1["a"] == ["192.0.2.10"]
        assert "mx.core.examplehost.net" in r1["mx"]
        assert len(r1["txt"]) == 1
        assert "v=spf1" in r1["txt"][0]

        r2 = records[1]
        assert r2["host"] == "nonexistent.examplepaint.com.br"
        assert r2["resolves"] is False
        assert "a" not in r2

    def test_parse_empty_and_corrupt_lines(self):
        assert parse_dns_records("") == []
        assert parse_dns_records("corrupt line\n{}") == []
