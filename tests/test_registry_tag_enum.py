"""
Unit tests for the registry_tag_enum adapter, parser, Tool wrapper, and
contract. requests is mocked; exact URLs, params, headers, and the read-only
verb are asserted. Fixtures follow the Docker Registry HTTP API V2 tags/list
shape and Docker Hub's anonymous token response; no live registry was queried.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.registry_tag_enum import execute as rte_execute
from tradecraft.adapters.registry_tag_enum import parse as rte_parse
from tradecraft.adapters.registry_tag_enum.execute import USER_AGENT
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.registry_tag_enum import RegistryTagEnum

# Docker Hub anonymous pull-token response (auth.docker.io/token).
DOCKER_HUB_TOKEN = json.dumps({
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature",
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature",
    "expires_in": 300,
    "issued_at": "2026-11-05T12:00:00.000000000Z",
})

NGINX_TAGS = json.dumps({
    "name": "library/nginx",
    "tags": ["1.25", "1.25-alpine", "1.27", "1.27-alpine", "latest", "mainline", "stable"],
})

# GET /v2/<name>/tags/list on a self-hosted registry that allows anonymous pulls.
SELF_HOSTED_TAGS = json.dumps({
    "name": "examplecorp/app",
    "tags": ["v1.0.0", "v1.0.1", "v1.1.0-rc1", "main"],
})

# Registry V2 error envelope for an unknown repository.
NAME_UNKNOWN = json.dumps({
    "errors": [{
        "code": "NAME_UNKNOWN",
        "message": "repository name not known to registry",
        "detail": {"name": "examplecorp/nope"},
    }]
})

# Registry V2 error envelope for a registry that requires auth.
UNAUTHORIZED = json.dumps({
    "errors": [{
        "code": "UNAUTHORIZED",
        "message": "authentication required",
        "detail": [{"Type": "repository", "Name": "examplecorp/private", "Action": "pull"}],
    }]
})


def _resp(status: int, text: str = ""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.json = lambda: json.loads(text)
    return r


# --- Docker Hub path ----------------------------------------------------------

def test_docker_hub_token_then_tags_exact_calls():
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(200, DOCKER_HUB_TOKEN),
        _resp(200, NGINX_TAGS),
    ]) as get:
        raw = rte_execute.execute("library/nginx", timeout=8)

    assert get.call_count == 2
    token_call, tags_call = get.call_args_list
    assert token_call.args[0] == "https://auth.docker.io/token"
    assert token_call.kwargs["params"] == {
        "service": "registry.docker.io",
        "scope": "repository:library/nginx:pull",
    }
    assert token_call.kwargs["headers"] == {"User-Agent": USER_AGENT}
    assert token_call.kwargs["timeout"] == 8
    assert token_call.kwargs["verify"] is False

    assert tags_call.args[0] == "https://registry-1.docker.io/v2/library/nginx/tags/list"
    assert tags_call.kwargs["headers"] == {
        "User-Agent": USER_AGENT,
        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature",
    }
    assert tags_call.kwargs["timeout"] == 8
    assert tags_call.kwargs["verify"] is False

    assert raw.error is None
    assert raw.registry == "registry-1.docker.io"
    assert raw.total_tags == 7
    assert "stable" in raw.tags


def test_docker_hub_token_failure_still_tries_tags_unauthenticated():
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(503, ""),
        _resp(200, NGINX_TAGS),
    ]) as get:
        raw = rte_execute.execute("library/nginx")
    tags_call = get.call_args_list[1]
    assert tags_call.kwargs["headers"] == {"User-Agent": USER_AGENT}
    assert raw.total_tags == 7


def test_docker_hub_token_network_error_still_tries_tags():
    with patch.object(rte_execute.requests, "get", side_effect=[
        requests.ConnectionError("auth down"),
        _resp(200, NGINX_TAGS),
    ]) as get:
        raw = rte_execute.execute("library/nginx")
    assert get.call_count == 2
    assert raw.total_tags == 7


# --- self-hosted registry -----------------------------------------------------

def test_self_hosted_registry_skips_token_and_uses_exact_url():
    with patch.object(rte_execute.requests, "get", return_value=_resp(200, SELF_HOSTED_TAGS)) as get:
        raw = rte_execute.execute("examplecorp/app", registry="registry.examplecorp.example:5000")
    assert get.call_count == 1
    assert get.call_args.args[0] == "https://registry.examplecorp.example:5000/v2/examplecorp/app/tags/list"
    assert get.call_args.kwargs["headers"] == {"User-Agent": USER_AGENT}
    assert get.call_args.kwargs["verify"] is False
    assert raw.total_tags == 4


def test_repository_is_stripped_of_slashes():
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(200, DOCKER_HUB_TOKEN), _resp(200, NGINX_TAGS),
    ]) as get:
        rte_execute.execute("  /library/nginx/  ")
    assert get.call_args_list[1].args[0] == "https://registry-1.docker.io/v2/library/nginx/tags/list"


# --- error and not-found classification ---------------------------------------

def test_401_is_error_requires_authentication():
    with patch.object(rte_execute.requests, "get", return_value=_resp(401, UNAUTHORIZED)):
        raw = rte_execute.execute("examplecorp/private", registry="registry.examplecorp.example")
    out = rte_parse.parse_registry_tag_result(raw)
    assert out == {
        "repository": "examplecorp/private",
        "registry": "registry.examplecorp.example",
        "error": "registry requires authentication this call did not provide",
    }


def test_404_is_reason_not_error():
    with patch.object(rte_execute.requests, "get", return_value=_resp(404, NAME_UNKNOWN)):
        raw = rte_execute.execute("examplecorp/nope", registry="registry.examplecorp.example")
    assert raw.error is None
    out = rte_parse.parse_registry_tag_result(raw)
    assert out == {
        "repository": "examplecorp/nope",
        "registry": "registry.examplecorp.example",
        "reason": "repository not found on this registry",
    }


def test_request_exception_is_error():
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(200, DOCKER_HUB_TOKEN),
        requests.Timeout("read timed out"),
    ]):
        raw = rte_execute.execute("library/nginx")
    assert "read timed out" in raw.error
    assert "error" in rte_parse.parse_registry_tag_result(raw)


def test_empty_repository_is_error():
    raw = rte_execute.execute("  ")
    assert raw.error == "no repository given"


# --- parser -------------------------------------------------------------------

def test_parse_sorts_tags_and_reports_total():
    with patch.object(rte_execute.requests, "get", return_value=_resp(200, SELF_HOSTED_TAGS)):
        raw = rte_execute.execute("examplecorp/app", registry="registry.examplecorp.example")
    out = rte_parse.parse_registry_tag_result(raw)
    assert out == {
        "repository": "examplecorp/app",
        "registry": "registry.examplecorp.example",
        "total_tags": 4,
        "tags": ["main", "v1.0.0", "v1.0.1", "v1.1.0-rc1"],
    }


def test_parse_empty_tags_list_is_reason():
    body = json.dumps({"name": "examplecorp/empty", "tags": None})
    with patch.object(rte_execute.requests, "get", return_value=_resp(200, body)):
        raw = rte_execute.execute("examplecorp/empty", registry="registry.examplecorp.example")
    out = rte_parse.parse_registry_tag_result(raw)
    assert out["reason"] == "repository exists but has no tags, or was not found"
    assert "tags" not in out


def test_parse_caps_at_200_with_truncated_flag():
    many = json.dumps({"name": "library/busybox", "tags": [f"1.{i}" for i in range(260)]})
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(200, DOCKER_HUB_TOKEN), _resp(200, many),
    ]):
        raw = rte_execute.execute("library/busybox")
    out = rte_parse.parse_registry_tag_result(raw)
    assert out["total_tags"] == 260
    assert len(out["tags"]) == 200
    assert out["truncated"] is True
    assert out["tags"] == sorted(out["tags"])


# --- Tool wrapper + contract --------------------------------------------------

def test_tool_wrapper_end_to_end():
    with patch.object(rte_execute.requests, "get", side_effect=[
        _resp(200, DOCKER_HUB_TOKEN), _resp(200, NGINX_TAGS),
    ]):
        out = RegistryTagEnum()(repository="library/nginx")
    assert out["total_tags"] == 7
    assert "stable" in out["tags"]


def test_contract_is_non_destructive_cloud_only():
    tool = RegistryTagEnum()
    assert tool.tool_id == "registry_tag_enum"
    assert tool.destructive is False
    assert tool.scope_param == "repository"
    assert tool.required_binary is None
    assert tool.spec.parameters["required"] == ["repository"]
    assert "registry_tag_enum" in load_profile("cloud")
    assert "registry_tag_enum" not in load_profile("web")
    assert any(t.tool_id == "registry_tag_enum" for t in ALL_TOOLS)
