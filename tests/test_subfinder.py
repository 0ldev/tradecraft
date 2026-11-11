import subprocess
from unittest.mock import patch

from tradecraft.adapters.subfinder import execute as subfinder_execute
from tradecraft.adapters.subfinder import parse as subfinder_parse
from tradecraft.tools.subfinder import Subfinder


def test_parse_normalizes_names_and_enforces_domain_boundary():
    output = (
        "API.Example.com.\napi.example.com\nexample.com\nnotexample.com\n"
        "api.example.com.evil.test\n[INF] found api.example.com\n"
        "https://api.example.com\n*.example.com\n-bad.example.com\n\n"
    )
    assert subfinder_parse.parse_subdomains(output, "Example.com.") == [
        "api.example.com", "example.com",
    ]


def test_empty_discovery_is_not_an_error():
    assert subfinder_parse.parse_subdomains("", "example.com") == []
    process = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=process):
        result = Subfinder().run("example.com")
    assert result == {"target": "example.com", "subdomains": []}


def test_execution_uses_expected_argv_and_timeout():
    process = subprocess.CompletedProcess([], 0, stdout="api.example.com\n", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        result = subfinder_execute.execute("example.com")
    run.assert_called_once_with(
        ["subfinder", "-d", "example.com", "-silent", "-all"],
        text=True, capture_output=True, timeout=120, stdin=subprocess.DEVNULL,
    )
    assert result.stdout == process.stdout
    assert result.error is None


def test_nonzero_exit_is_not_empty_success():
    process = subprocess.CompletedProcess([], 1, stdout="", stderr="source failure")
    with patch("subprocess.run", return_value=process):
        result = Subfinder().run("example.com")
    assert result["error"] == "subfinder failed: source failure"


def test_extract_facts_and_evidence_on_discovery():
    tool = Subfinder()
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

    result["evidence_id"] = "subfinder:example.com"
    facts = tool.extract_facts({"target": "example.com"}, result)
    # port 0 is the sentinel for a domain-wide fact with no real port
    # (subfinder never probes any actual service) -- see
    # tradecraft/tools/interactsh.py for the existing convention this
    # matches. A real port like 80 would risk this fact silently merging
    # into (host, 80)'s record alongside an actual HTTP-port-80 service
    # fact from nmap_scan/httpx_probe on the same apex.
    assert facts == [{
        "host": "example.com", "port": 0,
        "subdomains_discovered": 2,
        "evidence": "subfinder:example.com",
    }]


def test_extract_facts_and_evidence_empty_without_subdomains():
    tool = Subfinder()
    result = {"target": "example.com", "subdomains": []}
    assert tool.extract_evidence({"target": "example.com"}, result) is None
    assert tool.extract_facts({"target": "example.com"}, result) == []


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert subfinder_execute.execute("example.com").error == "subfinder executable not found"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("subfinder", 120)):
        assert subfinder_execute.execute("example.com").error == "subfinder timed out after 120s"
