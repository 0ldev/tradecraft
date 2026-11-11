"""
Unit tests for identity_auth_bypass adapter and tool layer.
All HTTP is mocked, either via an injected session or by patching
requests.get directly; no live requests.
"""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

import requests

from tradecraft.adapters.identity_auth_bypass import execute as iab_execute
from tradecraft.adapters.identity_auth_bypass import parse as iab_parse
from tradecraft.tools.identity_auth_bypass import IdentityAuthBypass


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# Signed-looking token (signature segment is arbitrary; the tool never verifies it).
TOKEN = f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': '42', 'role': 'user'})}.c2ln"


def _resp(status: int):
    r = MagicMock()
    r.status_code = status
    return r


def _session_with(statuses_by_path: dict):
    """statuses_by_path: {path: (baseline_status, forged_status)}. Routes by URL suffix."""
    session = MagicMock(spec=requests.Session)

    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        baseline_s, forged_s = statuses_by_path.get(path, (404, 404))
        if headers and "Authorization" in headers:
            return _resp(forged_s)
        return _resp(baseline_s)

    session.get.side_effect = fake_get
    return session


def test_normalize_base_url():
    assert iab_parse.normalize_base_url("api.example.com") == "https://api.example.com"
    assert iab_parse.normalize_base_url("http://x.test/") == "http://x.test"
    assert iab_parse.normalize_base_url("   ") == ""


def test_normalize_base_url_scheme_detection_is_case_insensitive():
    # A mixed/upper-case scheme must be recognized as already schemed,
    # not double-prefixed into "https://HTTPS://host".
    assert iab_parse.normalize_base_url("HTTPS://host.com") == "HTTPS://host.com"
    assert iab_parse.normalize_base_url("Http://host.com") == "Http://host.com"


def test_candidate_paths_explicit_first_capped_and_deduped():
    paths = iab_parse.candidate_paths("/api/me")
    assert paths[0] == "/api/me"
    assert len(paths) == len(set(paths)) == iab_parse.MAX_CANDIDATE_PATHS
    assert iab_parse.candidate_paths("v2/session")[0] == "/v2/session"


def test_execute_forges_alg_none_and_sends_bearer_header():
    session = _session_with({})
    raw = iab_execute.execute("https://api.example.com", TOKEN, session=session)
    assert "error" not in raw
    forged = raw["forged_token"]
    assert forged.endswith(".")  # alg=none: empty signature segment
    header = json.loads(base64.urlsafe_b64decode(forged.split(".")[0] + "=="))
    assert header["alg"] == "none"
    # Every probe pair sent a baseline (no header) and a forged (Bearer) request
    sent = session.get.call_args_list
    assert len(sent) == 2 * iab_parse.MAX_CANDIDATE_PATHS
    assert "headers" not in sent[0].kwargs
    assert sent[1].kwargs["headers"] == {"Authorization": f"Bearer {forged}"}


def test_execute_stops_at_first_bypass_and_reports_it():
    session = _session_with({"/api/me": (401, 200), "/api/user": (401, 200)})
    raw = iab_execute.execute("https://api.example.com", TOKEN, session=session)
    assert raw["probes"][-1]["path"] == "/api/me"
    assert len(raw["probes"]) == 1
    parsed = iab_parse.parse_result(raw)
    assert parsed["vulnerable"] is True
    assert parsed["identity_url"] == "https://api.example.com/api/me"
    assert parsed["technique"] == "none_algorithm_forgery"


def test_no_bypass_when_baseline_is_not_rejected():
    # Public endpoint: baseline 200, forged 200 -> not a bypass
    session = _session_with({"/me": (200, 200)})
    parsed = iab_parse.parse_result(iab_execute.execute("https://x.test", TOKEN, session=session))
    assert parsed["vulnerable"] is False
    assert "identity_url" not in parsed


def test_no_bypass_when_forged_token_rejected():
    session = _session_with({"/me": (401, 401)})
    parsed = iab_parse.parse_result(iab_execute.execute("https://x.test", TOKEN, session=session))
    assert parsed["vulnerable"] is False


def test_request_exception_records_probe_with_error_instead_of_dropping_it():
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("refused")
    raw = iab_execute.execute("https://x.test", TOKEN, session=session)
    # Every candidate path was attempted and recorded (not silently
    # dropped), each with no status and an explicit error.
    assert len(raw["probes"]) == iab_parse.MAX_CANDIDATE_PATHS
    for probe in raw["probes"]:
        assert probe["baseline_status"] is None
        assert probe["forged_status"] is None
        assert "refused" in probe["error"]
    parsed = iab_parse.parse_result(raw)
    assert parsed["vulnerable"] is False
    assert parsed["probes_sent"] == iab_parse.MAX_CANDIDATE_PATHS


def test_forged_request_failure_preserves_already_obtained_baseline():
    session = MagicMock(spec=requests.Session)

    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        if headers and "Authorization" in headers:
            raise requests.Timeout("forged request timed out")
        return _resp(401)

    session.get.side_effect = fake_get
    raw = iab_execute.execute("https://x.test", TOKEN, test_path="/api/me", session=session)
    probe = raw["probes"][0]
    assert probe["baseline_status"] == 401  # preserved, not discarded
    assert probe["forged_status"] is None
    assert "timed out" in probe["error"]


def test_production_path_uses_independent_requests_get_not_a_shared_session(monkeypatch):
    """Without an injected session (the real production path), execute()
    must call the top-level requests.get directly -- each call is
    independent, so a cookie set by the baseline response can never be
    sent back on the forged request, or carried into a later path's
    probes. Matches jwt_analyze's run_differential pattern exactly."""
    import tradecraft.adapters.identity_auth_bypass.execute as iab_execute_module

    received_headers = []

    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        received_headers.append(headers)
        r = MagicMock()
        r.status_code = 200 if headers else 401
        return r

    monkeypatch.setattr(iab_execute_module.requests, "get", fake_get)
    raw = iab_execute.execute("https://x.test", TOKEN, test_path="/api/me")
    assert received_headers == [None, {"Authorization": f"Bearer {raw['forged_token']}"}]
    assert raw["probes"][0]["baseline_status"] == 401
    assert raw["probes"][0]["forged_status"] == 200


def test_requests_not_following_redirects():
    session = _session_with({"/api/me": (401, 200)})
    iab_execute.execute("https://x.test", TOKEN, test_path="/api/me", session=session)
    for call in session.get.call_args_list:
        assert call.kwargs.get("allow_redirects") is False


def test_invalid_token_returns_error():
    raw = iab_execute.execute("https://x.test", "not-a-jwt", session=_session_with({}))
    parsed = iab_parse.parse_result(raw)
    assert "invalid JWT" in parsed["error"]
    assert parsed["vulnerable"] is False


def test_tool_run_and_facts_and_evidence(monkeypatch):
    session = _session_with({"/rest/user/whoami": (403, 200)})
    original = iab_execute.execute

    def with_session(**kwargs):
        return original(session=session, **kwargs)

    monkeypatch.setattr(iab_execute, "execute", with_session)
    tool = IdentityAuthBypass()
    params = {"target": "https://api.example.com", "token": TOKEN}
    result = tool.run(**params)
    assert result["vulnerable"] is True

    facts = tool.extract_facts(params, result)
    assert facts == [{"host": "api.example.com", "port": 443, "identity_alg_none_bypass": True}]

    evidence = tool.extract_evidence(params, result)
    assert evidence is not None
    host, data = evidence
    assert host == "api.example.com"
    assert data["forged_status"] == 200
    assert "_full_evidence" not in result


def test_tool_no_facts_or_evidence_when_not_vulnerable(monkeypatch):
    session = _session_with({})
    original = iab_execute.execute
    monkeypatch.setattr(iab_execute, "execute", lambda **kw: original(session=session, **kw))
    tool = IdentityAuthBypass()
    params = {"target": "https://api.example.com", "token": TOKEN}
    result = tool.run(**params)
    assert result["vulnerable"] is False
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None
