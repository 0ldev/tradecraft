from __future__ import annotations

import subprocess
from unittest.mock import patch

from tradecraft.adapters.subjs import execute as subjs_execute
from tradecraft.adapters.subjs import parse as subjs_parse
from tradecraft.tools.subjs import Subjs

REAL_CAPTURED_SUBJS_OUTPUT = """https://www.googletagmanager.com/gtag/js?id=G-WQ0VEEQNM9
https://examplepaint.com.br/frontend/dist/js/jquery.min.js
https://examplepaint.com.br/frontend/dist/js/jquery.validate.min.js
https://examplepaint.com.br/frontend/dist/js/bootstrap.min.js
https://examplepaint.com.br/frontend/dist/js/slick.js
https://examplepaint.com.br/frontend/dist/js/aos.js
https://examplepaint.com.br/frontend/dist/js/main.min.js
https://examplepaint.com.br/frontend/dist/js/util.js
https://examplepaint.com.br/frontend/dist/js/sweetalert2.js
https://www.google.com/recaptcha/api.js
"""


def test_normalize_url():
    assert subjs_execute.normalize_url("examplepaint.com.br") == "http://examplepaint.com.br"
    assert subjs_execute.normalize_url("https://examplepaint.com.br") == "https://examplepaint.com.br"
    assert subjs_execute.normalize_url("http://127.0.0.1:8080/app") == "http://127.0.0.1:8080/app"


def test_build_argv():
    assert subjs_execute.build_argv() == ["subjs"]


def test_parse_real_captured_subjs_output():
    urls = subjs_parse.parse_js_urls(REAL_CAPTURED_SUBJS_OUTPUT)
    assert len(urls) == 10
    assert urls[0] == "https://www.googletagmanager.com/gtag/js?id=G-WQ0VEEQNM9"
    assert urls[1] == "https://examplepaint.com.br/frontend/dist/js/jquery.min.js"
    assert urls[-1] == "https://www.google.com/recaptcha/api.js"


def test_parse_cache_busting_and_variants():
    raw = (
        "https://example.com/assets/app.js?v=1.2.3\n"
        "https://example.com/modules/core.mjs?build=2026#hash\n"
        "https://example.com/bundle.cjs\n"
        "https://example.com/style.css\n"
        "https://example.com/image.png?v=4\n"
        "https://example.com/api/v1/user.json\n"
    )
    urls = subjs_parse.parse_js_urls(raw)
    assert urls == [
        "https://example.com/assets/app.js?v=1.2.3",
        "https://example.com/modules/core.mjs?build=2026#hash",
        "https://example.com/bundle.cjs",
    ]


def test_parse_deduplicates_and_ignores_noise():
    assert subjs_parse.parse_js_urls("") == []
    assert subjs_parse.parse_js_urls("   \n\n  ") == []
    raw = (
        "https://example.com/app.js\n"
        "https://example.com/app.js\n"
        "   \n"
        "invalid url line\n"
        "https://example.com/other.js\n"
    )
    assert subjs_parse.parse_js_urls(raw) == [
        "https://example.com/app.js",
        "https://example.com/other.js",
    ]


def test_execute_success():
    proc = subprocess.CompletedProcess(
        args=["subjs"],
        returncode=0,
        stdout="https://example.com/main.js\n",
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/local/bin/subjs"), patch(
        "subprocess.run", return_value=proc
    ) as mock_run:
        result = subjs_execute.execute("example.com")

    assert result.error is None
    assert result.returncode == 0
    assert result.stdout == "https://example.com/main.js\n"
    mock_run.assert_called_once_with(
        ["subjs"],
        input="http://example.com\n",
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_execute_errors():
    # Empty target
    assert subjs_execute.execute("").error == "Target cannot be empty"

    # Missing binary
    with patch("shutil.which", return_value=None):
        assert subjs_execute.execute("example.com").error == "subjs executable not found on PATH"

    # FileNotFoundError in subprocess
    with patch("shutil.which", return_value="/bin/subjs"), patch(
        "subprocess.run", side_effect=FileNotFoundError
    ):
        assert subjs_execute.execute("example.com").error == "subjs executable not found on PATH"

    # TimeoutExpired
    with patch("shutil.which", return_value="/bin/subjs"), patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired("subjs", 120)
    ):
        assert "timed out after 120s" in subjs_execute.execute("example.com").error


def test_tool_run():
    tool = Subjs()

    # Success case
    proc = subprocess.CompletedProcess(
        args=["subjs"],
        returncode=0,
        stdout=REAL_CAPTURED_SUBJS_OUTPUT,
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/local/bin/subjs"), patch(
        "subprocess.run", return_value=proc
    ):
        res = tool.run("https://examplepaint.com.br")

    assert res["target"] == "https://examplepaint.com.br"
    assert len(res["js_urls"]) == 10
    assert "error" not in res

    evidence = tool.extract_evidence({"target": "https://examplepaint.com.br"}, res)
    assert evidence is not None
    ev_target, ev_data = evidence
    assert ev_target == "examplepaint.com.br"
    assert len(ev_data["js_urls"]) == 10
    assert "_full_evidence" not in res

    res["evidence_id"] = "subjs:examplepaint.com.br"
    facts = tool.extract_facts({"target": "https://examplepaint.com.br"}, res)
    assert facts == [{
        "host": "examplepaint.com.br", "port": 443,
        "js_urls_discovered": 10,
        "evidence": "subjs:examplepaint.com.br",
    }]

    # Error propagation
    with patch("shutil.which", return_value=None):
        err_res = tool.run("example.com")
        assert err_res["error"] == "subjs executable not found on PATH"
        assert err_res["js_urls"] == []
        assert tool.extract_evidence({"target": "example.com"}, err_res) is None
        assert tool.extract_facts({"target": "example.com"}, err_res) == []

    # Nonzero exit without output
    proc_fail = subprocess.CompletedProcess(
        args=["subjs"],
        returncode=1,
        stdout="",
        stderr="network failure",
    )
    with patch("shutil.which", return_value="/usr/local/bin/subjs"), patch(
        "subprocess.run", return_value=proc_fail
    ):
        fail_res = tool.run("example.com")
        assert fail_res["error"] == "network failure"
        assert fail_res["js_urls"] == []
