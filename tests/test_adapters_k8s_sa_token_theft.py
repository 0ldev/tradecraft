"""
Unit tests for k8s_sa_token_theft adapter (execute.py and parse.py).
"""
import base64
import json
from unittest.mock import patch

import pytest
import requests

from tradecraft.adapters.k8s_sa_token_theft.execute import (
    K8S_NAMESPACE_FILE_URI,
    K8S_TOKEN_FILE_URI,
    PLACEHOLDER,
    HttpExchange,
    RawK8sSaTokenResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.k8s_sa_token_theft.parse import parse


def _make_jwt(claims: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"fakesig123").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


SAMPLE_CLAIMS = {
    "iss": "kubernetes/serviceaccount",
    "sub": "system:serviceaccount:production:backend-api",
    "kubernetes.io": {
        "namespace": "production",
        "serviceaccount": {
            "name": "backend-api",
            "uid": "12345678-1234-1234-1234-1234567890ab",
        },
    },
}
SAMPLE_JWT = _make_jwt(SAMPLE_CLAIMS)
SAMPLE_NAMESPACE = "production\n"


class FakeResponder:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        sorted_patterns = sorted(self.routes.keys(), key=len, reverse=True)
        for pattern in sorted_patterns:
            if pattern in url or (isinstance(kwargs.get("data"), str) and pattern in kwargs.get("data", "")):
                response = self.routes[pattern]
                if isinstance(response, Exception):
                    raise response
                status, text = response
                resp = requests.Response()
                resp.status_code = status
                resp._content = text.encode("utf-8")
                resp.encoding = "utf-8"
                return resp
        resp = requests.Response()
        resp.status_code = 404
        resp._content = b"Not Found"
        return resp


def test_normalize_target_url():
    assert normalize_target_url("http://example.com/api?url=__SSRF__") == "http://example.com/api?url=__SSRF__"
    assert normalize_target_url("example.com/api?url=__SSRF__") == "https://example.com/api?url=__SSRF__"
    assert normalize_target_url("   ") == ""


def test_validation_errors():
    res = execute(target="")
    assert res.error == "empty target URL"

    res = execute(target="http://example.com", inject_location="invalid")
    assert "inject_location must be one of" in res.error

    res = execute(target="http://example.com/api", inject_location="url_param")
    assert "target URL missing the '__SSRF__' placeholder" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template="")
    assert "json_body_template is required" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template="{invalid")
    assert "json_body_template is not valid JSON" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template='{"url": "test"}')
    assert "missing the '__SSRF__' placeholder" in res.error

    res = execute(target="http://example.com", inject_location="header", header_name="")
    assert "header_name is required" in res.error


def test_successful_token_and_namespace_extraction():
    routes = {
        "serviceaccount/token": (200, SAMPLE_JWT),
        "serviceaccount/namespace": (200, SAMPLE_NAMESPACE),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.k8s_sa_token_theft.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.k8s.local/preview?url=__SSRF__",
            inject_location="url_param",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 2
    assert raw.raw_token_text == SAMPLE_JWT
    assert raw.raw_namespace_text == "production"

    parsed = parse(raw)
    assert parsed["token_obtained"] is True
    assert parsed["token"] == SAMPLE_JWT
    assert parsed["namespace"] == "production"
    assert parsed["claims"]["iss"] == "kubernetes/serviceaccount"
    assert parsed["claims"]["sub"] == "system:serviceaccount:production:backend-api"
    assert parsed["claims"]["kubernetes.io"]["serviceaccount"]["name"] == "backend-api"
    assert "Successfully extracted Kubernetes service account token" in parsed["summary"]


def test_token_extraction_json_body():
    routes = {
        "serviceaccount/token": (200, SAMPLE_JWT),
        "serviceaccount/namespace": (404, "Not Found"),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.k8s_sa_token_theft.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="https://target.com/api/fetch",
            inject_location="json_body",
            json_body_template='{"url": "__SSRF__"}',
        )

    assert raw.error is None
    assert len(raw.exchanges) == 2
    parsed = parse(raw)
    assert parsed["token_obtained"] is True
    # Namespace inferred from JWT claims since namespace file was 404
    assert parsed["namespace"] == "production"


def test_file_scheme_blocked_403():
    routes = {
        "serviceaccount/token": (403, "Forbidden - file scheme disabled"),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.k8s_sa_token_theft.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://target.com/fetch?url=__SSRF__",
            inject_location="url_param",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 1
    parsed = parse(raw)
    assert parsed["token_obtained"] is False
    assert "403" in parsed["summary"]


def test_network_failure_handling():
    responder = FakeResponder({
        "serviceaccount/token": requests.exceptions.ConnectTimeout("Connection timed out"),
    })

    with patch("tradecraft.adapters.k8s_sa_token_theft.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://target.com/fetch?url=__SSRF__",
            inject_location="url_param",
        )

    assert len(raw.exchanges) == 1
    assert "Connection timed out" in raw.exchanges[0].error
    parsed = parse(raw)
    assert parsed["token_obtained"] is False
    assert "Connection timed out" in parsed["summary"]
