"""
Unit tests for openapi_spec_discovery_probe adapter (execution and parsing).
"""
import json
from unittest.mock import MagicMock, patch

from tradecraft.adapters.openapi_spec_discovery_probe.execute import (
    SPEC_PATHS,
    OpenApiSpecDiscoveryResult,
    SpecHit,
    execute,
    normalize_base_url,
)
from tradecraft.adapters.openapi_spec_discovery_probe.parse import parse

SWAGGER_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Example API", "version": "1.2.3"},
    "paths": {
        "/users/{id}": {"get": {}, "put": {}},
        "/admin/reset": {"post": {}},
        "/health": {"get": {}},
    },
}


def _resp(status_code, body=""):
    r = MagicMock()
    r.status_code = status_code
    r.text = body
    return r


def test_normalize_base_url():
    assert normalize_base_url("api.example.com") == "https://api.example.com"


@patch("tradecraft.adapters.openapi_spec_discovery_probe.execute.requests.get")
def test_execute_finds_swagger_json(mock_get):
    def side_effect(url, **kwargs):
        if url == "https://api.example.com/swagger.json":
            return _resp(200, json.dumps(SWAGGER_SPEC))
        return _resp(404, "not found")

    mock_get.side_effect = side_effect
    out = execute("api.example.com", timeout=5)
    assert out.checked_paths == len(SPEC_PATHS)
    assert len(out.hits) == 1
    assert out.hits[0].path == "/swagger.json"
    assert out.hits[0].title == "Example API"
    assert out.hits[0].api_version == "1.2.3"
    assert out.hits[0].spec_version == "2.0"


@patch("tradecraft.adapters.openapi_spec_discovery_probe.execute.requests.get")
def test_execute_yaml_spec_parses(mock_get):
    yaml_body = """
openapi: "3.0.0"
info:
  title: YAML API
  version: "2.0.0"
paths:
  /items:
    get: {}
"""

    def side_effect(url, **kwargs):
        if url == "https://api.example.com/openapi.yaml":
            return _resp(200, yaml_body)
        return _resp(404, "")

    mock_get.side_effect = side_effect
    out = execute("api.example.com", timeout=5)
    assert len(out.hits) == 1
    assert out.hits[0].title == "YAML API"
    assert out.hits[0].spec_version == "3.0.0"


@patch("tradecraft.adapters.openapi_spec_discovery_probe.execute.requests.get")
def test_execute_ignores_200_that_is_not_a_spec(mock_get):
    mock_get.return_value = _resp(200, "<html>not a spec</html>")
    out = execute("api.example.com", timeout=5)
    assert out.hits == []


@patch("tradecraft.adapters.openapi_spec_discovery_probe.execute.requests.get")
def test_execute_ignores_non_200(mock_get):
    mock_get.return_value = _resp(404, "")
    out = execute("api.example.com", timeout=5)
    assert out.hits == []


def test_execute_invalid_target():
    out = execute("   ")
    assert out.error is not None


def test_parse_extracts_endpoints_and_flags_admin():
    hit = SpecHit(path="/swagger.json", status_code=200, spec_version="2.0", title="Example API",
                  api_version="1.2.3", raw_spec=SWAGGER_SPEC)
    res = OpenApiSpecDiscoveryResult(target="api.example.com", base_url="https://api.example.com",
                                      hits=[hit], checked_paths=10)
    out = parse(res)
    spec = out["specs_found"][0]
    assert spec["endpoint_count"] == 4
    assert "POST /admin/reset" in spec["of_interest"]
    assert "GET /health" not in spec["of_interest"]
    assert set(spec["endpoints"]) == {"GET /users/{id}", "PUT /users/{id}", "POST /admin/reset", "GET /health"}
