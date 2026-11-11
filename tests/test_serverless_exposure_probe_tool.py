"""Unit tests for the serverless_exposure_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.serverless_exposure_probe.execute import RawServerlessExposureResult
from tradecraft.tools.serverless_exposure_probe import ServerlessExposureProbe


def test_tool_attributes():
    tool = ServerlessExposureProbe()
    assert tool.tool_id == "serverless_exposure_probe"
    assert tool.scope_param == "candidates"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = ServerlessExposureProbe()
    failed = RawServerlessExposureResult(provider="aws", error="no candidate URLs resolved from 'candidates'")
    with patch("tradecraft.tools.serverless_exposure_probe.sep_execute.execute", return_value=failed):
        result = tool.run(provider="aws", candidates="")
    assert result == {"provider": "aws", "error": "no candidate URLs resolved from 'candidates'"}


def test_extract_facts_severity_depends_on_leaked_secrets():
    tool = ServerlessExposureProbe()
    params = {"candidates": "abc123xyz"}
    result = {
        "provider": "aws",
        "results": [
            {"url": "https://abc123xyz.lambda-url.us-east-1.on.aws/", "status_code": 200, "classification": "exposed", "leaked_secrets": ["AWS_SECRET_ACCESS_KEY=x"]},
            {"url": "https://other.lambda-url.us-east-1.on.aws/", "status_code": 403, "classification": "exists_auth_required"},
        ],
    }
    facts = tool.extract_facts(params, dict(result))
    assert len(facts) == 1
    assert facts[0]["host"] == "abc123xyz.lambda-url.us-east-1.on.aws"
    assert facts[0]["severity"] == "high"


def test_extract_facts_empty_on_error():
    tool = ServerlessExposureProbe()
    assert tool.extract_facts({}, {"error": "boom"}) == []
