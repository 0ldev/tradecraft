from __future__ import annotations

import re
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import requests
from requests.structures import CaseInsensitiveDict

from tradecraft.adapters.crlf_injection_probe.execute import (
    DEFAULT_INJECTED_HEADER_NAME,
    build_probe_url,
    execute,
)
from tradecraft.adapters.crlf_injection_probe.parse import parse

MARKER_RE = re.compile(r"crlf[0-9a-f]{16}")
GET_PATH = "tradecraft.adapters.crlf_injection_probe.execute.requests.get"


def _marker_from_url(url: str) -> str:
    match = MARKER_RE.search(url)
    assert match, f"no marker in probe URL: {url}"
    return match.group(0)


def _response(headers: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = CaseInsensitiveDict(headers)
    return resp


class TestCrlfInjectionProbeAdapter:
    def test_confirmed_injection_same_named_header(self):
        def fake_get(url, **kwargs):
            marker = _marker_from_url(url)
            return _response({
                "Content-Type": "text/html",
                DEFAULT_INJECTED_HEADER_NAME: marker,
            })

        with patch(GET_PATH, side_effect=fake_get):
            raw = execute(target="https://example.com/redirect?url=/home", parameter="url")
        parsed = parse(raw)

        assert raw.error is None
        assert parsed["injected_header_found"] is True
        assert parsed["vulnerable"] is True
        assert parsed["injected_value_in_other_header"] is None
        assert parsed["error"] is None

    def test_confirmed_injection_marker_in_other_header(self):
        def fake_get(url, **kwargs):
            marker = _marker_from_url(url)
            return _response({"Some-Other-Header": f"value-{marker}"})

        with patch(GET_PATH, side_effect=fake_get):
            raw = execute(target="https://example.com/redirect?url=/home", parameter="url")
        parsed = parse(raw)

        assert parsed["injected_header_found"] is False
        assert parsed["injected_value_in_other_header"] == "Some-Other-Header"
        assert parsed["vulnerable"] is True

    def test_no_injection(self):
        with patch(GET_PATH, return_value=_response({"Content-Type": "text/html"})):
            raw = execute(target="https://example.com/redirect?url=/home", parameter="url")
        parsed = parse(raw)

        assert parsed["injected_header_found"] is False
        assert parsed["injected_value_in_other_header"] is None
        assert parsed["vulnerable"] is False

    def test_request_exception(self):
        with patch(GET_PATH, side_effect=requests.RequestException("boom")):
            raw = execute(target="https://example.com/", parameter="url")
        parsed = parse(raw)

        assert raw.error is not None
        assert "probe request failed" in parsed["error"]
        assert "vulnerable" not in parsed

    def test_empty_target(self):
        raw = execute(target="", parameter="url")
        assert raw.error is not None
        assert "empty target URL" in raw.error

    def test_empty_parameter(self):
        raw = execute(target="https://example.com", parameter="")
        assert raw.error is not None
        assert "missing required parameter" in raw.error

    def test_build_probe_url_keeps_crlf_unmangled(self):
        url = build_probe_url(
            "https://example.com/redirect?url=/home&keep=1",
            "url",
            DEFAULT_INJECTED_HEADER_NAME,
            "crlf0123456789abcdef",
        )
        query = urlsplit(url).query
        assert "%0d%0a" in query
        assert "%250d" not in query
        assert "%250a" not in query
        assert "keep=1" in query
