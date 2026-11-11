"""
Unit tests for cloud_identity_pool_probe adapter (execution and parsing).
"""
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.cloud_identity_pool_probe.execute import (
    CloudIdentityPoolResult,
    IdentityPoolAttempt,
    _infer_region,
    execute,
    probe_identity_pool,
)
from tradecraft.adapters.cloud_identity_pool_probe.parse import parse

POOL_ID = "us-east-1:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"


def _resp(status_code, payload=None):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = payload or {}
    return r


def test_infer_region():
    assert _infer_region(POOL_ID) == "us-east-1"
    assert _infer_region("no-colon-here") == ""


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.requests.post")
def test_probe_identity_pool_vulnerable(mock_post):
    mock_post.side_effect = [
        _resp(200, {"IdentityId": "us-east-1:identity-123"}),
        _resp(200, {"IdentityId": "us-east-1:identity-123", "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE", "SecretKey": "secret", "SessionToken": "token",
        }}),
    ]
    res = probe_identity_pool(POOL_ID, timeout=5.0)
    assert res.region == "us-east-1"
    assert res.identity_id == "us-east-1:identity-123"
    assert res.credentials_obtained is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.access_key_id == "ASIAEXAMPLE"


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.requests.post")
def test_probe_identity_pool_identity_creation_denied(mock_post):
    mock_post.return_value = _resp(400, {"__type": "NotAuthorizedException", "message": "Unauthenticated access is not supported"})
    res = probe_identity_pool(POOL_ID, timeout=5.0)
    assert res.status == "identity_creation_denied"
    assert res.vulnerable is False


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.requests.post")
def test_probe_identity_pool_credentials_denied(mock_post):
    mock_post.side_effect = [
        _resp(200, {"IdentityId": "us-east-1:identity-123"}),
        _resp(400, {"__type": "NotAuthorizedException", "message": "denied"}),
    ]
    res = probe_identity_pool(POOL_ID, timeout=5.0)
    assert res.identity_id == "us-east-1:identity-123"
    assert res.status == "credentials_denied"
    assert res.vulnerable is False


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.requests.post")
def test_probe_identity_pool_request_error(mock_post):
    mock_post.side_effect = requests.RequestException("connection reset")
    res = probe_identity_pool(POOL_ID, timeout=5.0)
    assert res.status == "error"


def test_probe_identity_pool_no_region():
    res = probe_identity_pool("no-colon-here", timeout=5.0)
    assert res.status == "error"
    assert "region" in res.error


# ---------------------------------------------------------------- execute()


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.probe_identity_pool")
def test_execute_caps_at_five_pool_ids(mock_probe):
    mock_probe.return_value = IdentityPoolAttempt(identity_pool_id="x", status="identity_creation_denied")
    many_ids = ",".join(f"us-east-1:{i}" for i in range(10))
    execute(many_ids)
    assert mock_probe.call_count == 5


def test_execute_no_pool_ids():
    out = execute("")
    assert out.error is not None


@patch("tradecraft.adapters.cloud_identity_pool_probe.execute.probe_identity_pool")
def test_execute_vulnerable_aggregates(mock_probe):
    mock_probe.return_value = IdentityPoolAttempt(
        identity_pool_id=POOL_ID, vulnerable=True, status="vulnerable", credentials_obtained=True,
    )
    out = execute(POOL_ID)
    assert out.vulnerable is True
    assert len(out.attempts) == 1


# ---------------------------------------------------------------- parse()


def test_parse_includes_findings_for_vulnerable_attempts():
    res = CloudIdentityPoolResult(
        target=POOL_ID,
        attempts=[IdentityPoolAttempt(
            identity_pool_id=POOL_ID, region="us-east-1", vulnerable=True, status="vulnerable",
            credentials_obtained=True, access_key_id="ASIAEXAMPLE",
        )],
        vulnerable=True,
        summary="VULNERABLE",
    )
    out = parse(res)
    assert len(out["findings"]) == 1
    assert "ASIAEXAMPLE" in out["findings"][0]
    assert out["attempts"][0]["access_key_id"] == "ASIAEXAMPLE"
