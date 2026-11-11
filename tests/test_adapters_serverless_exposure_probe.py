"""Unit tests for serverless_exposure_probe adapter. Mocks requests.get."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.serverless_exposure_probe.execute import _candidate_urls, execute
from tradecraft.adapters.serverless_exposure_probe.parse import parse


def test_candidate_urls_aws_default_region():
    urls = _candidate_urls("aws", "abc123xyz", None)
    assert urls == ["https://abc123xyz.lambda-url.us-east-1.on.aws/"]


def test_candidate_urls_aws_explicit_region():
    urls = _candidate_urls("aws", "abc123xyz:eu-west-1", None)
    assert urls == ["https://abc123xyz.lambda-url.eu-west-1.on.aws/"]


def test_candidate_urls_azure_expands_function_names():
    urls = _candidate_urls("azure", "examplecorp-prod", "default,health")
    assert urls == [
        "https://examplecorp-prod.azurewebsites.net/api/default",
        "https://examplecorp-prod.azurewebsites.net/api/health",
    ]


def test_candidate_urls_gcp_triple():
    urls = _candidate_urls("gcp", "us-central1:my-project:my-func", None)
    assert urls == ["https://us-central1-my-project.cloudfunctions.net/my-func"]


def test_candidate_urls_full_url_passthrough():
    urls = _candidate_urls("aws", "https://custom.example.com/fn", None)
    assert urls == ["https://custom.example.com/fn"]


def _mock_response(status_code=200, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_execute_unsupported_provider_errors():
    result = execute(provider="bogus", candidates="x")
    assert result.error is not None


def test_execute_and_parse_flags_exposed_with_leaked_secret():
    with patch("tradecraft.adapters.serverless_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=200, text='{"status":"ok","AWS_SECRET_ACCESS_KEY":"wJalrXUtnFEMI/K7MDENG/bPxRfiCY"}')
        raw = execute(provider="aws", candidates="abc123xyz")
    result = parse(raw)
    assert result["exposed_count"] == 1
    assert result["leaked_secrets_total"] >= 1
    assert result["results"][0]["classification"] == "exposed"


def test_execute_and_parse_auth_required_not_exposed():
    with patch("tradecraft.adapters.serverless_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=403, text="Forbidden")
        raw = execute(provider="aws", candidates="abc123xyz")
    result = parse(raw)
    assert result["exposed_count"] == 0
    assert result["results"][0]["classification"] == "exists_auth_required"
