from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.auth_bootstrap import execute as auth_execute
from tradecraft.adapters.auth_bootstrap import parse as auth_parse
from tradecraft.tools.auth_bootstrap import AuthBootstrap


def test_normalize_target_url():
    assert auth_parse.normalize_target_url("app.example.com") == "https://app.example.com"
    assert auth_parse.normalize_target_url("http://app.example.com") == "http://app.example.com"
    assert auth_parse.normalize_target_url("https://app.example.com:8443") == "https://app.example.com:8443"


def test_generate_account_credentials():
    email, password = auth_parse.generate_account_credentials(suffix="test123456")
    assert email == "tradecraft_probe_test123456@example.com"
    assert "test123456" in password
    assert len(password) > 10


def test_build_registration_payloads():
    payloads = auth_parse.build_registration_payloads("test@example.com", "Password!123")
    assert len(payloads) == 4
    assert payloads[0] == {"email": "test@example.com", "password": "Password!123"}
    assert payloads[1] == {"username": "test@example.com", "password": "Password!123"}


def test_extract_session_token():
    nested_data = {"authentication": {"token": "jwt_nested_123"}}
    assert auth_parse.extract_session_token(nested_data, {}, {}) == "jwt_nested_123"

    json_data = {"access_token": "token_access_456"}
    assert auth_parse.extract_session_token(json_data, {}, {}) == "token_access_456"

    # 3. Header Bearer
    assert auth_parse.extract_session_token(None, {"Authorization": "Bearer tok_header_789"}, {}) == "tok_header_789"

    # 4. Cookie fallback
    assert auth_parse.extract_session_token(None, {}, {"session_id": "sid_abc"}) == "session_id=sid_abc"

    # 5. Empty/no match
    assert auth_parse.extract_session_token({}, {"Content-Type": "text/html"}, {"theme": "dark"}) is None


def test_execute_success():
    reg_resp = MagicMock(status_code=201)
    login_resp = MagicMock(status_code=200, headers={}, cookies=MagicMock())
    login_resp.json.return_value = {"token": "auth_token_xyz"}
    login_resp.cookies.get_dict.return_value = {}

    with patch("requests.Session") as mock_session_cls:
        session_mock = MagicMock()
        session_mock.post.side_effect = [reg_resp, login_resp]
        mock_session_cls.return_value = session_mock

        res = auth_execute.execute(
            target="https://target.local",
            register_path="/api/register",
            login_path="/api/login",
        )

    assert res.registered is True
    assert res.session_token == "auth_token_xyz"
    assert res.registration_endpoint == "https://target.local/api/register"
    assert res.login_endpoint == "https://target.local/api/login"
    assert res.error is None
    assert "tradecraft_probe_" in res.email_used


def test_execute_success_token_returned_directly_by_registration():
    """Some APIs (e.g. Supabase's /auth/v1/signup) return a session token
    directly in the registration response, with no separate login step
    at all. No login call should be attempted once the registration
    response itself carries a token."""
    reg_resp = MagicMock(status_code=200, headers={})
    reg_resp.json.return_value = {"access_token": "supabase_token_abc", "token_type": "bearer"}
    reg_resp.cookies.get_dict.return_value = {}

    with patch("requests.Session") as mock_session_cls:
        session_mock = MagicMock()
        session_mock.post.return_value = reg_resp
        mock_session_cls.return_value = session_mock

        res = auth_execute.execute(
            target="https://whiteboard.example.app",
            register_path="/auth/v1/signup",
        )

    assert res.registered is True
    assert res.session_token == "supabase_token_abc"
    assert res.registration_endpoint == "https://whiteboard.example.app/auth/v1/signup"
    assert res.login_endpoint is None
    assert res.error is None
    # Only the registration POST happened -- no separate login attempt.
    assert session_mock.post.call_count == 1


def test_execute_failure():
    fail_resp = MagicMock(status_code=404)
    with patch("requests.Session") as mock_session_cls:
        session_mock = MagicMock()
        session_mock.post.return_value = fail_resp
        mock_session_cls.return_value = session_mock

        res = auth_execute.execute(target="https://target.local")

    assert res.registered is False
    assert res.session_token is None
    assert "failed across probed endpoints" in res.error


def test_tool_destructive_and_evidence():
    tool = AuthBootstrap()
    assert tool.destructive is True

    raw = auth_execute.RawAuthBootstrapResult(
        registered=True,
        session_token="sample_jwt_token",
        email_used="tradecraft_probe_1@example.com",
        registration_endpoint="https://example.com/register",
        login_endpoint="https://example.com/login",
    )

    with patch("tradecraft.adapters.auth_bootstrap.execute.execute", return_value=raw):
        result = tool.run(target="https://example.com")

    assert result["registered"] is True
    assert result["session_token"] == "sample_jwt_token"
    assert result["email_used"] == "tradecraft_probe_1@example.com"

    evidence = tool.extract_evidence({"target": "https://example.com"}, result)
    assert evidence is not None
    host, full = evidence
    assert host == "example.com"
    assert full["session_token"] == "sample_jwt_token"
    assert full["email_used"] == "tradecraft_probe_1@example.com"

    # Facts extraction remains empty (credentials are evidence, not facts)
    facts = tool.extract_facts({"target": "https://example.com"}, result)
    assert facts == []


def test_auth_bootstrap_excluded_from_loop_by_default():
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    memory = EngagementMemory()

    # Default: allow_destructive=False
    tools_default = _build_tool_map(memory, tool_ids=["auth_bootstrap"], allow_destructive=False)
    assert "auth_bootstrap" not in tools_default

    # With allow_destructive=True
    tools_allowed = _build_tool_map(memory, tool_ids=["auth_bootstrap"], allow_destructive=True)
    assert "auth_bootstrap" in tools_allowed

