from __future__ import annotations

import subprocess
from unittest.mock import patch

from tradecraft.adapters.amass import execute as amass_execute
from tradecraft.adapters.amass import parse as amass_parse
from tradecraft.tools.amass import Amass


def test_build_argv():
    argv = amass_execute.build_argv("example.com")
    assert argv == [
        "amass",
        "enum",
        "-d",
        "example.com",
        "-silent",
        "-active",
        "-timeout",
        "3",
    ]


def test_parse_normalizes_names_and_enforces_domain_boundary():
    output = (
        "API.Example.com.\napi.example.com\nexample.com\nnotexample.com\n"
        "api.example.com.evil.test\n[INF] found api.example.com\n"
        "https://api.example.com\n*.example.com\n-bad.example.com\n\n"
        "admin.corp.example.com\n"
    )
    assert amass_parse.parse_subdomains(output, "Example.com.") == [
        "admin.corp.example.com",
        "api.example.com",
        "example.com",
    ]


def test_parse_real_captured_amass_output():
    raw_output = """examplepaint.com.br
www.examplepaint.com.br
mail.examplepaint.com.br
autodiscover.examplepaint.com.br
cpanel.examplepaint.com.br
webdisk.examplepaint.com.br
webmail.examplepaint.com.br
cpcontacts.examplepaint.com.br
cpcalendars.examplepaint.com.br
"""
    parsed = amass_parse.parse_subdomains(raw_output, "examplepaint.com.br")
    assert len(parsed) == 9
    assert "www.examplepaint.com.br" in parsed
    assert "examplepaint.com.br" in parsed
    assert "webmail.examplepaint.com.br" in parsed


def test_empty_discovery_is_not_an_error():
    assert amass_parse.parse_subdomains("", "example.com") == []
    process = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=process):
        result = Amass().run("example.com")
    assert result == {"target": "example.com", "subdomains": []}


def test_execution_uses_expected_argv_and_timeout():
    process = subprocess.CompletedProcess([], 0, stdout="api.example.com\n", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        result = amass_execute.execute("example.com")
    run.assert_called_once_with(
        amass_execute.build_argv("example.com"),
        capture_output=True,
        text=True,
        timeout=240,
        stdin=subprocess.DEVNULL,
    )
    assert result.stdout == process.stdout
    assert result.error is None


def test_nonzero_exit_is_not_empty_success():
    process = subprocess.CompletedProcess([], 1, stdout="", stderr="enumeration failed")
    with patch("subprocess.run", return_value=process):
        result = Amass().run("example.com")
    assert result["error"] == "amass failed: enumeration failed"
    assert result["subdomains"] == []


def test_extract_facts_and_evidence_on_discovery():
    tool = Amass()
    # Go through run() so the result carries the same _full_evidence key the
    # real tool sets when it finds subdomains.
    process = subprocess.CompletedProcess([], 0, stdout="api.example.com\nwww.example.com\n", stderr="")
    with patch("subprocess.run", return_value=process):
        result = tool.run("example.com")
    assert result["subdomains"] == ["api.example.com", "www.example.com"]

    evidence = tool.extract_evidence({"target": "example.com"}, result)
    assert evidence == (
        "example.com",
        {"target": "example.com", "subdomains": ["api.example.com", "www.example.com"]},
    )
    assert "_full_evidence" not in result

    result["evidence_id"] = "amass:example.com"
    facts = tool.extract_facts({"target": "example.com"}, result)
    # port 0 is the sentinel for a domain-wide fact with no real port
    # (amass never probes any actual service) -- see
    # tradecraft/tools/interactsh.py for the existing convention this
    # matches. A real port like 80 would risk this fact silently merging
    # into (host, 80)'s record alongside an actual HTTP-port-80 service
    # fact from nmap_scan/httpx_probe on the same apex.
    assert facts == [{
        "host": "example.com", "port": 0,
        "subdomains_discovered": 2,
        "evidence": "amass:example.com",
    }]


def test_extract_facts_and_evidence_empty_without_subdomains():
    tool = Amass()
    result = {"target": "example.com", "subdomains": []}
    assert tool.extract_evidence({"target": "example.com"}, result) is None
    assert tool.extract_facts({"target": "example.com"}, result) == []


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert amass_execute.execute("example.com").error == "amass executable not found on PATH"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("amass", 240)):
        error = amass_execute.execute("example.com").error
        assert "amass timed out after 240s" in error
        assert "-timeout=3m" in error
