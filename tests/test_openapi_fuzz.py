from __future__ import annotations

import json
from unittest.mock import MagicMock

from tradecraft.adapters.openapi_fuzz import execute as fuzz_execute
from tradecraft.adapters.openapi_fuzz import parse as fuzz_parse
from tradecraft.tools.openapi_fuzz import OpenApiFuzz

SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/v1/public": {"get": {"summary": "Public endpoint"}},
        "/api/v1/admin/users": {"get": {"summary": "Admin users"}},
        "/api/v1/items/{id}": {"post": {"summary": "Create item"}},
    },
}


def test_parse_spec_endpoints():
    eps = fuzz_execute.parse_spec_endpoints(SAMPLE_SPEC)
    assert len(eps) == 3
    assert {"method": "GET", "path": "/api/v1/public"} in eps
    assert {"method": "GET", "path": "/api/v1/admin/users"} in eps
    assert {"method": "POST", "path": "/api/v1/items/{id}"} in eps


def test_execute_empty_target():
    res = fuzz_execute.execute("")
    assert res.error == "empty target URL"


def test_execute_success_with_spec_content():
    mock_session = MagicMock()
    mock_resp_public = MagicMock(status_code=200, text="public data")
    mock_resp_admin = MagicMock(status_code=200, text="sensitive user list")
    mock_resp_post = MagicMock(status_code=201, text="created")

    def fake_get(url, **kwargs):
        if "admin" in url:
            return mock_resp_admin
        return mock_resp_public

    mock_session.get.side_effect = fake_get
    mock_session.post.return_value = mock_resp_post

    res = fuzz_execute.execute(
        target="https://api.corp.local",
        spec_content=json.dumps(SAMPLE_SPEC),
        session=mock_session,
    )
    assert res.error is None
    assert len(res.endpoints_tested) == 3

    parsed = fuzz_parse.parse_openapi_fuzz_result(res)
    assert parsed["endpoints_tested"] == 3
    assert parsed["anomalies_found"] >= 1
    assert any("/api/v1/admin/users" in a["path"] for a in parsed["anomalies"])


def test_tool_glue():
    tool = OpenApiFuzz()
    assert tool.tool_id == "openapi_fuzz"
    assert tool.required_binary is None
    assert tool.is_available() is True


def test_tool_run_and_facts():
    tool = OpenApiFuzz()
    mock_session = MagicMock()
    mock_resp_admin = MagicMock(status_code=200, text="admin area")
    mock_session.get.return_value = mock_resp_admin
    mock_session.post.return_value = MagicMock(status_code=403, text="forbidden")

    with unittest_mock_session(mock_session):
        res = tool.run(
            target="https://api.corp.local",
            spec_content=json.dumps(SAMPLE_SPEC),
        )
        assert res["anomalies_found"] >= 1
        facts = tool.extract_facts({"target": "https://api.corp.local"}, res)
        assert len(facts) == 1
        assert facts[0]["host"] == "api.corp.local"
        assert facts[0]["port"] == 443
        assert facts[0]["api_anomalies_found"] is True


def unittest_mock_session(session_instance):
    from unittest.mock import patch
    return patch("requests.Session", return_value=session_instance)
