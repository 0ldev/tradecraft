"""
Unit tests for the azure_tenant_recon adapter, parser, Tool wrapper, and
contract. requests is mocked; exact URLs, headers, and bodies are asserted.
Fixture bodies follow the documented shapes of the OIDC well-known document
and the GetCredentialType response; no live tenant was queried.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.azure_tenant_recon import execute as att_execute
from tradecraft.adapters.azure_tenant_recon import parse as att_parse
from tradecraft.adapters.azure_tenant_recon.execute import MAX_USERNAMES, USER_AGENT
from tradecraft.tools.azure_tenant_recon import AzureTenantRecon
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS

TENANT = "9f1c2a6e-3b4d-4e5f-8a7b-0c1d2e3f4a5b"

# Shape of https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
OIDC_OK = json.dumps({
    "token_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt"],
    "jwks_uri": f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
    "issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0",
    "authorization_endpoint": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize",
    "tenant_region_scope": "NA",
    "cloud_instance_name": "microsoftonline.com",
    "cloud_graph_host_name": "graph.windows.net",
    "msgraph_host": "graph.microsoft.com",
    "rbac_url": "https://pas.windows.net",
})

# Shape of a GetCredentialType response (managed domain, user exists).
CRED_EXISTS = json.dumps({
    "Username": "admin@example.com",
    "Display": "admin@example.com",
    "IfExistsResult": 0,
    "IsUnmanaged": False,
    "ThrottleStatus": 0,
    "Credentials": {"PrefCredential": 1, "HasPassword": True, "RemoteNgcParams": None},
    "NameSpaceType": "Managed",
    "Domain": "example.com",
    "FederationFlags": 0,
    "CloudInstanceName": "microsoftonline.com",
})
CRED_MISSING = json.dumps({
    "Username": "nobody@example.com",
    "Display": "nobody@example.com",
    "IfExistsResult": 1,
    "IsUnmanaged": False,
    "ThrottleStatus": 0,
    "Credentials": {"PrefCredential": 1, "HasPassword": False},
    "NameSpaceType": "Managed",
    "Domain": "example.com",
    "FederationFlags": 0,
    "CloudInstanceName": "microsoftonline.com",
})
CRED_THROTTLED = json.dumps({
    "Username": "info@example.com",
    "IfExistsResult": -1,
    "ThrottleStatus": 1,
    "NameSpaceType": "Federated",
    "Domain": "example.com",
})


def _resp(status: int, text: str = ""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


# --- tenant discovery ---------------------------------------------------------

def test_discovery_url_headers_and_tenant_extraction():
    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)) as get:
        raw = att_execute.execute("Example.COM")
    get.assert_called_once()
    assert get.call_args.args[0] == "https://login.microsoftonline.com/example.com/.well-known/openid-configuration"
    assert get.call_args.kwargs == {
        "headers": {"User-Agent": USER_AGENT},
        "timeout": 10,
        "verify": False,
    }
    assert raw.is_azure_ad is True
    assert raw.tenant_id == TENANT
    assert raw.domain == "example.com"


def test_non_200_discovery_means_not_azure_ad_not_error():
    with patch.object(att_execute.requests, "get", return_value=_resp(400, '{"error":"invalid_tenant"}')):
        raw = att_execute.execute("example.org", usernames="a@example.org")
    assert raw.error is None
    assert raw.is_azure_ad is False
    assert raw.checks == []  # username loop skipped entirely
    out = att_parse.parse_azure_tenant_result(raw)
    assert out == {
        "domain": "example.org",
        "is_azure_ad": False,
        "reason": "domain is not backed by Azure AD / Entra ID",
    }


def test_network_error_during_discovery_is_top_level_error():
    with patch.object(att_execute.requests, "get", side_effect=requests.ConnectionError("dns failure")):
        raw = att_execute.execute("example.com")
    assert raw.error is not None and "dns failure" in raw.error
    assert att_parse.parse_azure_tenant_result(raw) == {"domain": "example.com", "error": raw.error}


def test_empty_domain_is_error():
    raw = att_execute.execute("   ")
    assert raw.error == "no domain given"


# --- GetCredentialType ---------------------------------------------------------

def test_username_post_url_headers_and_body_exact():
    responses = [_resp(200, OIDC_OK), _resp(200, CRED_EXISTS)]
    with patch.object(att_execute.requests, "get", return_value=responses[0]), \
         patch.object(att_execute.requests, "post", return_value=responses[1]) as post:
        raw = att_execute.execute("example.com", usernames="admin@example.com")
    # First POST is the domain-level namespace probe; the second is the username.
    assert post.call_count == 2
    assert json.loads(post.call_args_list[0].kwargs["data"]) == {
        "Username": "tradecraft-namespace-probe@example.com"
    }
    assert post.call_args.args[0] == "https://login.microsoftonline.com/common/GetCredentialType"
    assert post.call_args.kwargs["headers"] == {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": USER_AGENT,
    }
    assert json.loads(post.call_args.kwargs["data"]) == {"Username": "admin@example.com"}
    assert post.call_args.kwargs["timeout"] == 10
    assert post.call_args.kwargs["verify"] is False
    assert raw.checks[0].exists is True
    assert raw.checks[0].namespace_type == "Managed"


def test_if_exists_result_mapping_and_throttle():
    bodies = {
        "tradecraft-namespace-probe@example.com": _resp(200, CRED_EXISTS),
        "admin@example.com": _resp(200, CRED_EXISTS),
        "nobody@example.com": _resp(200, CRED_MISSING),
        "info@example.com": _resp(200, CRED_THROTTLED),
    }

    def fake_post(url, data, **kwargs):
        return bodies[json.loads(data)["Username"]]

    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", side_effect=fake_post):
        raw = att_execute.execute(
            "example.com", usernames="admin@example.com, nobody@example.com ,info@example.com"
        )
    by = {c.username: c for c in raw.checks}
    assert by["admin@example.com"].exists is True
    assert by["nobody@example.com"].exists is False
    assert by["info@example.com"].exists is None
    assert by["info@example.com"].throttle_status == -1
    assert by["info@example.com"].namespace_type == "Federated"

    out = att_parse.parse_azure_tenant_result(raw)
    assert out["existing_usernames"] == ["admin@example.com"]
    assert out["checked_count"] == 3
    assert out["namespace_types"] == {
        "admin@example.com": "Managed",
        "nobody@example.com": "Managed",
        "info@example.com": "Federated",
    }


def test_usernames_are_deduped_and_capped_at_25():
    many = [f"user{i}@example.com" for i in range(30)]
    usernames = ",".join(many + ["user0@example.com"])  # duplicate of the first
    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", return_value=_resp(200, CRED_MISSING)) as post:
        raw = att_execute.execute("example.com", usernames=usernames)
    assert MAX_USERNAMES == 25
    assert post.call_count == 26  # 25 usernames plus the one domain namespace probe
    sent = [json.loads(c.kwargs["data"])["Username"] for c in post.call_args_list[1:]]
    assert sent == many[:25]
    assert len(set(sent)) == 25


def test_per_username_request_error_is_recorded_and_loop_continues():
    def fake_post(url, data, **kwargs):
        if "boom" in data:
            raise requests.Timeout("timed out")
        return _resp(200, CRED_EXISTS)

    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", side_effect=fake_post):
        raw = att_execute.execute("example.com", usernames="boom@example.com,admin@example.com")
    assert raw.checks[0].error and "timed out" in raw.checks[0].error
    assert raw.checks[1].exists is True
    out = att_parse.parse_azure_tenant_result(raw)
    assert out["existing_usernames"] == ["admin@example.com"]
    assert out["errors"][0]["username"] == "boom@example.com"


def test_no_usernames_still_reports_tenant_id_and_makes_no_post():
    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", return_value=_resp(200, CRED_EXISTS)) as post:
        raw = att_execute.execute("example.com")
    # Only the domain namespace probe is sent; no username is checked.
    assert post.call_count == 1
    assert json.loads(post.call_args.kwargs["data"]) == {
        "Username": "tradecraft-namespace-probe@example.com"
    }
    out = att_parse.parse_azure_tenant_result(raw)
    assert out["tenant_id"] == TENANT
    assert out["domain_namespace_type"] == "Managed"
    assert out["existing_usernames"] == []
    assert out["checked_count"] == 0


# --- Tool wrapper + contract --------------------------------------------------

def test_tool_wrapper_end_to_end():
    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", return_value=_resp(200, CRED_EXISTS)):
        out = AzureTenantRecon()(domain="example.com", usernames="admin@example.com")
    assert out["is_azure_ad"] is True
    assert out["existing_usernames"] == ["admin@example.com"]


def test_contract_is_non_destructive_cloud_only():
    tool = AzureTenantRecon()
    assert tool.tool_id == "azure_tenant_recon"
    assert tool.destructive is False
    assert tool.scope_param == "domain"
    assert tool.required_binary is None
    assert tool.spec.parameters["required"] == ["domain"]
    assert "azure_tenant_recon" in load_profile("cloud")
    assert "azure_tenant_recon" not in load_profile("web")
    assert any(t.tool_id == "azure_tenant_recon" for t in ALL_TOOLS)


@pytest.mark.parametrize("code", [5, 6])
def test_undefined_if_exists_codes_stay_unresolved_not_guessed(code):
    body = json.dumps({"IfExistsResult": code, "ThrottleStatus": 0, "NameSpaceType": "Managed"})
    with patch.object(att_execute.requests, "get", return_value=_resp(200, OIDC_OK)), \
         patch.object(att_execute.requests, "post", return_value=_resp(200, body)):
        raw = att_execute.execute("example.com", usernames="someone@example.com")
    check = raw.checks[0]
    assert check.exists is None
    assert check.throttle_status is None
    assert check.if_exists_result == code
    out = att_parse.parse_azure_tenant_result(raw)
    assert out["existing_usernames"] == []
    assert out["unresolved_usernames"] == [
        {"username": "someone@example.com", "if_exists_result": code}
    ]
