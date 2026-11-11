"""
Unit tests for sqli_login adapter and tool layer.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.sqli_login import execute as sqli_execute
from tradecraft.adapters.sqli_login import parse as sqli_parse
from tradecraft.tools.sqli_login import SqliLogin


def test_normalize_target_url():
    assert sqli_parse.normalize_target_url("target.com") == "http://target.com"
    assert sqli_parse.normalize_target_url("https://target.com/login") == "https://target.com/login"
    assert sqli_parse.normalize_target_url("   ") == ""


def test_parse_host_port():
    assert sqli_parse.parse_host_port("http://target.com") == ("target.com", 80)
    assert sqli_parse.parse_host_port("https://target.com:8443/login") == ("target.com", 8443)


def test_resolve_candidate_urls():
    # Specific login path provided
    urls1 = sqli_parse.resolve_candidate_urls("https://target.com", login_path="/custom/login")
    assert urls1 == ["https://target.com/custom/login"]

    # Target already has path
    urls2 = sqli_parse.resolve_candidate_urls("https://target.com/admin/login.php")
    assert urls2 == ["https://target.com/admin/login.php"]

    # Target is base host -> generates default candidates
    urls3 = sqli_parse.resolve_candidate_urls("https://target.com")
    assert len(urls3) == len(sqli_parse.DEFAULT_LOGIN_PATHS)
    assert "https://target.com/login" in urls3
    assert "https://target.com/wp-login.php" in urls3


def test_extract_token_from_response_json():
    data = {"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}
    token, auth_type = sqli_parse.extract_token_from_response(data, {}, {}, 200)
    assert token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    assert auth_type == "bearer"


def test_extract_token_from_response_auth_header():
    headers = {"Authorization": "Bearer secret_bearer_token"}
    token, auth_type = sqli_parse.extract_token_from_response(None, headers, {}, 200)
    assert token == "secret_bearer_token"
    assert auth_type == "bearer"


def test_extract_token_from_response_cookie():
    cookies = {"PHPSESSID": "somesessionid12345"}
    token, auth_type = sqli_parse.extract_token_from_response(None, {}, cookies, 200)
    assert token == "PHPSESSID=somesessionid12345"
    assert auth_type == "session"


def test_is_login_bypass():
    # Token present -> bypass True
    assert sqli_parse.is_login_bypass(401, {}, 200, {}, "some_token") is True

    # 302 redirect with new session cookie
    assert sqli_parse.is_login_bypass(200, {}, 302, {"session": "abc"}, None) is True

    # Status changed from 401 to 200 with session cookie
    assert sqli_parse.is_login_bypass(401, {}, 200, {"connect.sid": "123"}, None) is True

    # No token, same 401 status -> bypass False
    assert sqli_parse.is_login_bypass(401, {}, 401, {}, None) is False


def test_execute_successful_bypass():
    mock_session = MagicMock()

    # Baseline response: 401 Unauthorized
    base_resp = MagicMock()
    base_resp.status_code = 401
    base_resp.cookies.get_dict.return_value = {}

    bypass_resp = MagicMock()
    bypass_resp.status_code = 200
    bypass_resp.headers = {}
    bypass_resp.cookies.get_dict.return_value = {}
    bypass_resp.json.return_value = {"token": "auth_token_xyz"}

    mock_session.post.side_effect = [base_resp, bypass_resp]

    res = sqli_execute.execute(
        target="https://target.com/api/login",
        session=mock_session,
    )

    assert res.success is True
    assert res.token == "auth_token_xyz"
    assert res.auth_type == "bearer"
    assert res.payload_used is not None
    assert res.field_used is not None


def test_execute_empty_target():
    res = sqli_execute.execute("")
    assert res.error == "empty target URL"


def test_tool_run_and_evidence():
    tool = SqliLogin()
    assert tool.tool_id == "sqli_login"
    assert tool.destructive is True

    with patch("tradecraft.adapters.sqli_login.execute.execute") as mock_exec:
        mock_raw = sqli_parse.RawSqliLoginResult(
            target="https://target.com/login",
            login_url_used="https://target.com/login",
            success=True,
            auth_type="bearer",
            token="bearer_token_abc",
            payload_used="' OR '1'='1",
            field_used="username",
        )
        mock_exec.return_value = mock_raw

        result = tool.run(target="https://target.com/login")
        assert result["success"] is True
        assert result["token"] == "bearer_token_abc"

        evidence = tool.extract_evidence({"target": "https://target.com/login"}, result)
        assert evidence is not None
        host, full = evidence
        assert host == "target.com"
        assert full["token"] == "bearer_token_abc"

        facts = tool.extract_facts({"target": "https://target.com/login"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "target.com"
        assert facts[0]["port"] == 443
        assert facts[0]["sqli_login_bypass"] is True
