"""
Unit tests for asn_discovery adapter (execution and parsing).
"""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.asn_discovery.execute import (
    RawAsnResult,
    execute,
    guess_org_name,
    is_private_target,
)
from tradecraft.adapters.asn_discovery.parse import parse_result


def test_is_private_target():
    assert is_private_target("127.0.0.1") is True
    assert is_private_target("localhost") is True
    assert is_private_target("192.168.1.50:8080") is True
    assert is_private_target("10.0.0.1") is True
    assert is_private_target("8.8.8.8") is False
    assert is_private_target("example.com") is False
    assert is_private_target("1.1.1.1:443") is False


def test_guess_org_name():
    assert guess_org_name("example.com") == "example"
    assert guess_org_name("sub.domain.example.com.br") == "example"
    assert guess_org_name("example.com.br") == "example"
    assert guess_org_name("https://api.examplepaint.com.br:8443") == "examplepaint"


def test_execute_private_target_skips_subprocess():
    res = execute("192.168.1.100")
    assert res.skipped_private is True
    assert res.asns == []
    assert res.cidrs == []


@patch("subprocess.run")
def test_execute_success(mock_run):
    whois_proc = MagicMock()
    whois_proc.stdout = "Found range: 198.51.100.0/24\n203.0.113.0/24 in whois"
    
    org_proc = MagicMock()
    org_proc.stdout = "AS13335, CLOUDFLARENET\n20940 AKAMAI\n"

    mock_run.side_effect = [whois_proc, org_proc]

    res = execute("example.com")
    assert res.skipped_private is False
    assert res.org_name == "example"
    assert "198.51.100.0/24" in res.cidrs
    assert "203.0.113.0/24" in res.cidrs
    assert "AS13335" in res.asns
    assert "AS20940" in res.asns


@patch("subprocess.run")
def test_execute_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError()
    res = execute("example.com")
    assert res.error == "amass executable not found in PATH"


def test_parse_result():
    raw = RawAsnResult(
        org_name="example",
        asns=["AS123", "AS123", "AS456"],
        cidrs=["1.1.1.0/24", "1.1.1.0/24"],
    )
    parsed = parse_result(raw)
    assert parsed["asns"] == ["AS123", "AS456"]
    assert parsed["cidrs"] == ["1.1.1.0/24"]
