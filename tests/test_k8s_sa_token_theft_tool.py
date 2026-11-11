"""
Unit tests for K8sSaTokenTheft tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.k8s_sa_token_theft.execute import (
    HttpExchange,
    RawK8sSaTokenResult,
)
from tradecraft.tools.k8s_sa_token_theft import K8sSaTokenTheft
from tradecraft.tools.registry import ALL_TOOLS

SAMPLE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6YXBwLXNhIn0.fakesig"


def test_tool_identity_and_contract():
    tool = K8sSaTokenTheft()
    assert tool.tool_id == "k8s_sa_token_theft"
    assert tool.spec.name == "k8s_sa_token_theft"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "k8s_sa_token_theft" for t in ALL_TOOLS)


def test_run_forwards_all_params_and_returns_parsed():
    tool = K8sSaTokenTheft()
    raw = RawK8sSaTokenResult(
        target="https://shop.example.com/api/preview?url=__SSRF__",
        inject_location="url_param",
        raw_token_text=SAMPLE_JWT,
        raw_namespace_text="default",
        exchanges=[
            HttpExchange(
                step="token_read",
                target_url="https://shop.example.com/api/preview?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token",
                injected_url="file:///var/run/secrets/kubernetes.io/serviceaccount/token",
                status_code=200,
            )
        ],
    )

    with patch("tradecraft.tools.k8s_sa_token_theft.theft_execute", return_value=raw) as mock_exec:
        out = tool.run(
            target="https://shop.example.com/api/preview?url=__SSRF__",
            inject_location="url_param",
            method="GET",
            json_body_template="",
            header_name="",
            timeout=8,
        )

    mock_exec.assert_called_once_with(
        target="https://shop.example.com/api/preview?url=__SSRF__",
        inject_location="url_param",
        method="GET",
        json_body_template="",
        header_name="",
        timeout=8,
    )
    assert out["token_obtained"] is True
    assert out["token"] == SAMPLE_JWT
    assert out["namespace"] == "default"


def test_extract_facts_with_obtained_token():
    tool = K8sSaTokenTheft()
    res = {
        "token_obtained": True,
        "token": SAMPLE_JWT,
        "namespace": "production",
        "claims": {
            "sub": "system:serviceaccount:production:frontend",
        },
    }

    facts = tool.extract_facts({"target": "https://shop.example.com/api/fetch?url=__SSRF__"}, res)
    assert len(facts) == 1
    assert facts[0]["host"] == "shop.example.com"
    assert facts[0]["port"] == 443
    assert facts[0]["credentials_obtained"] is True
    assert facts[0]["severity"] == "critical"
    assert facts[0]["k8s_namespace"] == "production"
    assert facts[0]["k8s_service_account"] == "system:serviceaccount:production:frontend"
    assert "Kubernetes service account token exposure via file:// SSRF" in facts[0]["vulnerability"]


def test_extract_facts_tested_without_token():
    tool = K8sSaTokenTheft()
    res = {
        "token_obtained": False,
        "summary": "Target returned 404",
    }

    facts = tool.extract_facts({"target": "https://target.com/fetch"}, res)
    assert len(facts) == 1
    assert facts[0]["k8s_token_ssrf_tested"] is True
    assert "vulnerability" not in facts[0]


def test_extract_facts_empty_on_error():
    tool = K8sSaTokenTheft()
    facts = tool.extract_facts({"target": "https://target.com"}, {"error": "failed to connect"})
    assert facts == []
