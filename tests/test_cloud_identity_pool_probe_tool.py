"""
Unit tests for CloudIdentityPoolProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.cloud_identity_pool_probe.execute import CloudIdentityPoolResult, IdentityPoolAttempt
from tradecraft.tools.cloud_identity_pool_probe import CloudIdentityPoolProbe

POOL_ID = "us-east-1:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"


def _vuln_result():
    return CloudIdentityPoolResult(
        target=POOL_ID,
        attempts=[IdentityPoolAttempt(
            identity_pool_id=POOL_ID, region="us-east-1", vulnerable=True, status="vulnerable",
            credentials_obtained=True, access_key_id="ASIAEXAMPLE", secret_key="secret", session_token="token",
        )],
        vulnerable=True,
        summary="VULNERABLE",
    )


def test_run_returns_parsed_result():
    tool = CloudIdentityPoolProbe()
    with patch("tradecraft.tools.cloud_identity_pool_probe.pool_execute", return_value=_vuln_result()):
        out = tool.run(POOL_ID)
    assert out["vulnerable"] is True
    assert out["attempts"][0]["access_key_id"] == "ASIAEXAMPLE"


def test_extract_facts_credentials_obtained_is_critical():
    tool = CloudIdentityPoolProbe()
    res = {
        "attempts": [{
            "identity_pool_id": POOL_ID, "region": "us-east-1", "credentials_obtained": True,
        }],
    }
    facts = tool.extract_facts({"identity_pool_id": POOL_ID}, res)
    assert len(facts) == 1
    assert facts[0]["severity"] == "critical"
    assert facts[0]["host"] == "cognito-identity.us-east-1.amazonaws.com"


def test_extract_facts_not_vulnerable_has_no_vulnerability_key():
    tool = CloudIdentityPoolProbe()
    res = {"attempts": [{"identity_pool_id": POOL_ID, "region": "us-east-1", "credentials_obtained": False}]}
    facts = tool.extract_facts({"identity_pool_id": POOL_ID}, res)
    assert "vulnerability" not in facts[0]
