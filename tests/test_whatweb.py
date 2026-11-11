import json
import subprocess
from unittest.mock import patch

from tradecraft.adapters.whatweb import execute as whatweb_execute
from tradecraft.adapters.whatweb import parse as whatweb_parse
from tradecraft.tools.whatweb import WhatWeb


def test_to_url_defaults_to_http():
    assert whatweb_execute.to_url("10.0.0.5") == "http://10.0.0.5"
    assert whatweb_execute.to_url("10.0.0.5:443") == "https://10.0.0.5:443"
    assert whatweb_execute.to_url("https://target.local") == "https://target.local"


def test_parse_fingerprint_extracts_tech_excluding_noise_plugins():
    stdout = json.dumps([{
        "target": "http://10.0.0.5",
        "plugins": {
            "WordPress": {"version": "6.4"},
            "PHP": {"version": None},
            "Title": {"string": ["Home"]},
            "Cookies": {"string": ["PHPSESSID"]},
        },
    }])
    fingerprint = whatweb_parse.parse_fingerprint(stdout)
    assert fingerprint == {
        "url": "http://10.0.0.5", "host": "10.0.0.5", "port": 80, "tech": ["PHP", "WordPress"],
    }


def test_parse_fingerprint_returns_none_for_empty_stdout():
    assert whatweb_parse.parse_fingerprint("") is None


def test_execution_uses_expected_argv_and_timeout():
    process = subprocess.CompletedProcess([], 0, stdout="[]", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        whatweb_execute.execute("10.0.0.5")
    run.assert_called_once_with(
        ["whatweb", "--log-json=-", "-q", "http://10.0.0.5"],
        text=True, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
    )


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert whatweb_execute.execute("10.0.0.5").error == "whatweb executable not found"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("whatweb", 60)):
        assert whatweb_execute.execute("10.0.0.5").error == "whatweb timed out after 60s"


def test_extract_facts_joins_tech_list_onto_reported_host_port():
    tool = WhatWeb()
    result = {"host": "10.0.0.5", "port": 80, "tech": ["PHP", "WordPress"]}
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{"host": "10.0.0.5", "port": 80, "whatweb_tech": "PHP, WordPress"}]


def test_extract_facts_empty_when_no_tech_detected():
    tool = WhatWeb()
    assert tool.extract_facts({"target": "10.0.0.5"}, {"host": "10.0.0.5", "port": 80, "tech": []}) == []
