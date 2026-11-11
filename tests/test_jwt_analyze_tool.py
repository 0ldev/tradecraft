import base64
import json
from unittest.mock import patch

from tradecraft.adapters.jwt_analyze.execute import DifferentialResult
from tradecraft.tools.jwt_analyze import JwtAnalyze


def _valid_token():
    h = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"user": "bob"}).encode()).decode().rstrip("=")
    return f"{h}.{p}.fake_sig"


def test_jwt_analyze_tool_invalid_token():
    tool = JwtAnalyze()
    res = tool.run("https://api.example.com", "not_a_jwt")
    assert "invalid JWT" in res["error"]


def test_jwt_analyze_tool_vulnerable():
    tool = JwtAnalyze()
    token = _valid_token()

    with patch("tradecraft.tools.jwt_analyze.jwt_execute.run_differential") as mock_diff:
        mock_diff.return_value = DifferentialResult(
            baseline_status=401,
            forged_status=200,
            error=None,
        )
        res = tool.run("https://api.example.com:8443/account", token)
        assert res["target"] == "https://api.example.com:8443/account"
        assert res["vulnerable"] is True
        assert res["baseline_status"] == 401
        assert res["forged_status"] == 200
        assert "forged_token" in res
        assert res["technique"] == "none_algorithm_forgery"

        # Fact extraction
        facts = tool.extract_facts({"target": "https://api.example.com:8443/account"}, res)
        assert facts == [{
            "host": "api.example.com",
            "port": 8443,
            "jwt_alg_none_bypass": "vulnerable",
        }]

        # Evidence extraction
        canonical, full = tool.extract_evidence({"target": "https://api.example.com:8443/account"}, res)
        assert canonical == "api.example.com:8443"
        assert full["vulnerable"] is True


def test_jwt_analyze_tool_not_vulnerable():
    tool = JwtAnalyze()
    token = _valid_token()

    with patch("tradecraft.tools.jwt_analyze.jwt_execute.run_differential") as mock_diff:
        mock_diff.return_value = DifferentialResult(
            baseline_status=401,
            forged_status=401,
            error=None,
        )
        res = tool.run("https://api.example.com/account", token)
        assert res["vulnerable"] is False

        # Facts extraction returns empty list
        facts = tool.extract_facts({"target": "https://api.example.com/account"}, res)
        assert facts == []
