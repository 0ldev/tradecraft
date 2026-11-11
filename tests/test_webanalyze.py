from __future__ import annotations

import subprocess
from unittest.mock import patch

from tradecraft.adapters.webanalyze import execute as webanalyze_execute
from tradecraft.adapters.webanalyze import parse as webanalyze_parse
from tradecraft.tools.webanalyze import Webanalyze

REAL_CAPTURED_WEBANALYZE_JSONL = r"""
 :: webanalyze        : v0.3.9
 :: workers           : 4
 :: technologies      : /tmp/technologies.json
{"hostname":"https://examplepaint.com.br","matches":[{"app":{"cats":["16"],"category_names":["Security"],"cookies":null,"headers":null,"meta":null,"html":[""],"scripts":["/recaptcha/api\\.js"],"url":[""],"website":"https://www.google.com/recaptcha/","implies":[""]},"app_name":"reCAPTCHA","matches":[["/recaptcha/api.js"]],"version":""},{"app":{"cats":["22"],"category_names":["Web servers"],"cookies":null,"headers":{"Server":"(?:Apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)HTTPD)\\;version:\\1"},"meta":null,"html":[""],"scripts":[""],"url":[""],"website":"https://httpd.apache.org/","implies":[""]},"app_name":"Apache HTTP Server","matches":[["Apache",""]],"version":""},{"app":{"cats":["27"],"category_names":["Programming languages"],"cookies":{"PHPSESSID":""},"headers":{"Server":"php/?([\\d.]+)?\\;version:\\1","X-Powered-By":"^php/?([\\d.]+)?\\;version:\\1"},"meta":null,"html":[""],"scripts":["\\.php(?:\\?|$)"],"url":["\\.php(?:$|\\?)"],"website":"https://php.net","implies":[""]},"app_name":"PHP","matches":[["PHP/5.6.40","5.6.40"]],"version":"5.6.40"}]}
"""


def test_normalize_url():
    assert webanalyze_execute.normalize_url("examplepaint.com.br") == "http://examplepaint.com.br"
    assert webanalyze_execute.normalize_url("https://examplepaint.com.br") == "https://examplepaint.com.br"
    assert webanalyze_execute.normalize_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_build_argv():
    argv_default = webanalyze_execute.build_argv("http://example.com")
    assert argv_default == ["webanalyze", "-host", "http://example.com", "-output", "json", "-silent"]

    argv_apps = webanalyze_execute.build_argv("http://example.com", apps_path="/tmp/technologies.json")
    assert argv_apps == [
        "webanalyze",
        "-host",
        "http://example.com",
        "-output",
        "json",
        "-silent",
        "-apps",
        "/tmp/technologies.json",
    ]


def test_host_port_from_target():
    assert webanalyze_parse.host_port_from_target("example.com") == ("example.com", 80)
    assert webanalyze_parse.host_port_from_target("https://example.com") == ("example.com", 443)
    assert webanalyze_parse.host_port_from_target("http://example.com:8080") == ("example.com", 8080)
    assert webanalyze_parse.host_port_from_target("https://example.com:8443") == ("example.com", 8443)


def test_parse_real_captured_webanalyze_output():
    techs = webanalyze_parse.parse_webanalyze_output(REAL_CAPTURED_WEBANALYZE_JSONL)
    assert techs == [
        {"name": "Apache HTTP Server", "version": ""},
        {"name": "PHP", "version": "5.6.40"},
        {"name": "reCAPTCHA", "version": ""},
    ]


def test_parse_handles_malformed_empty_and_noise():
    assert webanalyze_parse.parse_webanalyze_output("") == []
    assert webanalyze_parse.parse_webanalyze_output("   \n\n  ") == []
    assert webanalyze_parse.parse_webanalyze_output(":: banner\nnot json\n{\"no_matches\": 1}") == []


def test_parse_deduplicates_and_preserves_version():
    jsonl = (
        '{"hostname":"http://test","matches":[{"app_name":"Nginx","version":""}]}\n'
        '{"hostname":"http://test","matches":[{"app_name":"Nginx","version":"1.18.0"}]}\n'
        '{"hostname":"http://test","matches":[{"app_name":"Nginx","version":""}]}\n'
    )
    techs = webanalyze_parse.parse_webanalyze_output(jsonl)
    assert techs == [{"name": "Nginx", "version": "1.18.0"}]


def test_execute_success():
    proc = subprocess.CompletedProcess(
        args=["webanalyze"],
        returncode=0,
        stdout='{"hostname":"http://example.com","matches":[{"app_name":"Apache","version":"2.4"}]}',
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/local/bin/webanalyze"), patch(
        "os.path.exists", return_value=True
    ), patch("subprocess.run", return_value=proc) as mock_run:
        result = webanalyze_execute.execute("example.com", apps_path="/tmp/technologies.json")

    assert result.error is None
    assert result.returncode == 0
    assert "Apache" in result.stdout
    mock_run.assert_called_once_with(
        ["webanalyze", "-host", "http://example.com", "-output", "json", "-silent", "-apps", "/tmp/technologies.json"],
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )


def test_execute_errors():
    # Empty target
    assert webanalyze_execute.execute("").error == "Target cannot be empty"

    # Binary not found on PATH
    with patch("shutil.which", return_value=None):
        assert webanalyze_execute.execute("example.com").error == "webanalyze executable not found on PATH"

    # FileNotFoundError on subprocess
    with patch("shutil.which", return_value="/bin/webanalyze"), patch(
        "os.path.exists", return_value=False
    ), patch("subprocess.run", side_effect=FileNotFoundError):
        assert webanalyze_execute.execute("example.com").error == "webanalyze executable not found on PATH"

    # TimeoutExpired
    with patch("shutil.which", return_value="/bin/webanalyze"), patch(
        "os.path.exists", return_value=False
    ), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("webanalyze", 120)):
        assert "timed out after 120s" in webanalyze_execute.execute("example.com").error


def test_tool_run_and_extract_facts():
    tool = Webanalyze()

    # Success case
    proc = subprocess.CompletedProcess(
        args=["webanalyze"],
        returncode=0,
        stdout=REAL_CAPTURED_WEBANALYZE_JSONL,
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/local/bin/webanalyze"), patch(
        "os.path.exists", return_value=True
    ), patch("subprocess.run", return_value=proc):
        res = tool.run("https://examplepaint.com.br")

    assert res["target"] == "https://examplepaint.com.br"
    assert res["host"] == "examplepaint.com.br"
    assert res["port"] == 443
    assert len(res["technologies"]) == 3

    facts = tool.extract_facts({"target": "https://examplepaint.com.br"}, res)
    assert facts == [
        {
            "host": "examplepaint.com.br",
            "port": 443,
            "webanalyze_tech": "Apache HTTP Server, PHP, reCAPTCHA",
        }
    ]

    # Empty tech yields empty facts
    assert tool.extract_facts({"target": "example.com"}, {"host": "example.com", "port": 80, "technologies": []}) == []

    # Error case in run
    with patch("shutil.which", return_value=None):
        err_res = tool.run("example.com")
        assert err_res["error"] == "webanalyze executable not found on PATH"
        assert err_res["technologies"] == []
