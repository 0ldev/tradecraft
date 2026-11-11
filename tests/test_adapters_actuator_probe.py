from unittest.mock import patch

import requests

from tradecraft.adapters.actuator_probe.execute import (
    ACTUATOR_PATHS,
    HIGH_VALUE,
    PathResult,
    RawActuatorResult,
    _looks_like_actuator,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.actuator_probe.parse import parse_actuator_result

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}

ACTUATOR_INDEX = (
    b'{"_links":{"self":{"href":"https://shop.example.com/actuator","templated":false},'
    b'"health":{"href":"https://shop.example.com/actuator/health","templated":false},'
    b'"env":{"href":"https://shop.example.com/actuator/env","templated":false}}}'
)
ENV_JSON = (
    b'{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig",'
    b'"properties":{"spring.datasource.password":{"value":"******"}}}]}'
)
HEALTH_DOWN = b'{"status":"DOWN","components":{"db":{"status":"DOWN"}}}'
HTML_404 = b"<!DOCTYPE html><html><head><title>Not Found</title></head><body>Not Found</body></html>"
HTML_200_CATCHALL = b"<!doctype html><html><body><div id=app></div></body></html>"
FORBIDDEN_HTML = b"<html><head><title>403 Forbidden</title></head><body>Access denied</body></html>"


class FakeResp:
    def __init__(self, status, body=b"", content_type=""):
        self.status_code = status
        self.content = body
        self.headers = {"Content-Type": content_type} if content_type else {}


def _responses(table):
    """table: {path: FakeResp}; anything unlisted is a 404 HTML page."""
    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        fake_get.calls.append({
            "url": url,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "verify": verify,
            "allow_redirects": allow_redirects,
        })
        base = "https://shop.example.com"
        path = url[len(base):]
        resp = table.get(path, FakeResp(404, HTML_404, "text/html;charset=UTF-8"))
        if isinstance(resp, Exception):
            raise resp
        return resp
    fake_get.calls = []
    return fake_get


# --- normalization / list ---------------------------------------------------

def test_path_list_is_26_entries_and_high_value_matches_spec():
    assert len(ACTUATOR_PATHS) == 26
    assert len(set(ACTUATOR_PATHS)) == 26
    assert HIGH_VALUE == {"env", "heapdump", "configprops", "mappings", "loggers", "httptrace", "trace", "dump"}


def test_normalize_target_url():
    assert normalize_target_url("shop.example.com") == "https://shop.example.com"
    assert normalize_target_url("http://shop.example.com:8080") == "http://shop.example.com:8080"
    assert normalize_target_url("") == ""


def test_empty_target_is_error_without_requests():
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get") as get:
        raw = execute("   ")
    assert raw.error == "empty target"
    get.assert_not_called()


# --- execute: exact URLs and headers ----------------------------------------

def test_execute_requests_every_path_with_exact_urls_and_options():
    fake = _responses({})
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://shop.example.com/", timeout=3)

    assert raw.target == "https://shop.example.com"
    assert [c["url"] for c in fake.calls] == [
        "https://shop.example.com" + p for p in ACTUATOR_PATHS
    ]
    for c in fake.calls:
        assert c["headers"] == UA
        assert c["timeout"] == 3
        assert c["verify"] is False
        assert c["allow_redirects"] is True
    assert len(raw.results) == 26


def test_looks_like_actuator_rules():
    assert _looks_like_actuator(200, "application/vnd.spring-boot.actuator.v3+json", b"") is True
    assert _looks_like_actuator(200, "text/plain", b'{"a":1}') is True
    assert _looks_like_actuator(200, "text/html", HTML_200_CATCHALL) is False
    assert _looks_like_actuator(401, "text/html", b"") is True
    assert _looks_like_actuator(403, "text/html", FORBIDDEN_HTML) is True
    assert _looks_like_actuator(404, "application/json", b"{}") is False
    assert _looks_like_actuator(503, "application/json", HEALTH_DOWN) is False


def test_execute_per_path_exception_is_isolated():
    fake = _responses({"/actuator/env": requests.ConnectionError("reset")})
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://shop.example.com")
    env = next(r for r in raw.results if r.path == "/actuator/env")
    assert env.error is not None and "reset" in env.error
    assert len(raw.results) == 26


# --- parse against realistic Spring Boot responses ---------------------------

def test_realistic_spring_boot_2_exposure_is_classified():
    table = {
        "/actuator": FakeResp(200, ACTUATOR_INDEX, "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8"),
        "/actuator/health": FakeResp(503, HEALTH_DOWN, "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8"),
        "/actuator/info": FakeResp(200, b"{}", "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8"),
        "/actuator/env": FakeResp(200, ENV_JSON, "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8"),
        "/actuator/heapdump": FakeResp(200, b"JAVA PROFILE 1.0.2", "application/octet-stream"),
        "/actuator/metrics": FakeResp(401, b'{"timestamp":"2026-11-05","status":401}', "application/json"),
    }
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get", side_effect=_responses(table)):
        raw = execute("https://shop.example.com")
    out = parse_actuator_result(raw)

    assert out["target"] == "https://shop.example.com"
    high = {e["path"] for e in out["high_value_exposures"]}
    low = {e["path"] for e in out["low_value_exposures"]}
    # env is JSON 200 -> hit (high); heapdump 200 octet-stream -> not an actuator response.
    assert high == {"/actuator/env"}
    # /actuator index, info and 401 metrics are low value; health 503 is not counted.
    assert low == {"/actuator", "/actuator/info", "/actuator/metrics"}
    assert out["total_hits"] == 4
    env = next(e for e in out["high_value_exposures"])
    assert env == {
        "path": "/actuator/env",
        "status": 200,
        "content_type": "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8",
    }


def test_legacy_unprefixed_endpoints_are_matched_by_last_segment():
    table = {
        "/env": FakeResp(200, ENV_JSON, "application/json"),
        "/trace": FakeResp(401, b"", "text/html"),
    }
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get", side_effect=_responses(table)):
        out = parse_actuator_result(execute("https://shop.example.com"))
    assert [e["path"] for e in out["high_value_exposures"]] == ["/env", "/trace"]
    assert out["low_value_exposures"] == []


def test_catch_all_html_pages_are_not_hits():
    table = {p: FakeResp(200, HTML_200_CATCHALL, "text/html") for p in ACTUATOR_PATHS}
    with patch("tradecraft.adapters.actuator_probe.execute.requests.get", side_effect=_responses(table)):
        out = parse_actuator_result(execute("https://shop.example.com"))
    assert out == {
        "target": "https://shop.example.com",
        "reason": "no actuator path responded as a live endpoint across 26 candidates",
    }


def test_parse_error_passthrough_and_no_hit_reason():
    assert parse_actuator_result(RawActuatorResult(target="t", error="x")) == {"target": "t", "error": "x"}
    raw = RawActuatorResult(target="t", results=[PathResult(path="/env", status=404)])
    assert parse_actuator_result(raw)["reason"].startswith("no actuator path responded")
