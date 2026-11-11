"""
Unit tests for cero adapter (execution and parsing).
"""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cero.execute import RawCeroResult, execute, normalize_target
from tradecraft.adapters.cero.parse import parse_domains


def test_normalize_target():
    assert normalize_target("example.com") == "example.com"
    assert normalize_target("https://sub.example.com/path") == "sub.example.com"
    assert normalize_target("http://target.local:8080") == "target.local"
    assert normalize_target("  EXAMPLE.COM  ") == "example.com"


def test_parse_domains_strips_wildcards_and_deduplicates():
    raw = [
        "*.example.com",
        "api.example.com",
        "api.example.com",
        "mail.example.com",
        "*.dev.example.com",
        "example.com",
    ]
    parsed = parse_domains(raw, "example.com")
    assert parsed == [
        "api.example.com",
        "dev.example.com",
        "example.com",
        "mail.example.com",
    ]


def test_parse_real_captured_cero_output():
    # Real captured output from cero examplepaint.com.br
    raw = [
        "cpcontacts.examplepaint.com.br",
        "*.examplepainttintas.com.br",
        "cpanel.examplepaint.com.br",
        "cpcalendars.examplepaint.com.br",
        "mail.examplepaint.com.br",
        "examplepaint.com.br",
        "examplepainttintas.com.br",
        "webdisk.examplepaint.com.br",
        "www.examplepaint.com.br",
    ]
    parsed = parse_domains(raw, "examplepaint.com.br")
    assert "examplepainttintas.com.br" in parsed
    assert "*.examplepainttintas.com.br" not in parsed
    assert len(parsed) == 8  # 8 distinct domains without wildcard prefix


@patch("subprocess.run")
def test_execute_success(mock_run):
    proc = MagicMock()
    proc.stdout = "sub1.example.com\nsub2.example.com\n"
    mock_run.return_value = proc

    res = execute("example.com", timeout=30)
    assert res.error is None
    assert res.domains == ["sub1.example.com", "sub2.example.com"]
    mock_run.assert_called_once_with(
        ["cero", "example.com"],
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )


@patch("subprocess.run")
def test_execute_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()
    res = execute("example.com")
    assert res.error == "cero executable not found in PATH"
    assert res.domains == []


@patch("subprocess.run")
def test_execute_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["cero"], timeout=10)
    res = execute("example.com")
    assert res.error == "cero execution timed out"
    assert res.domains == []
