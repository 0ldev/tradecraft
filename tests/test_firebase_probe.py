"""
Unit tests for the firebase_probe adapter, parser, Tool wrapper, and contract.
requests is mocked; exact URLs, headers, and the read-only verb are asserted.
Fixture bodies follow the documented Realtime Database REST and Firestore REST
(v1 documents.list) shapes; no live project was queried.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.firebase_probe import execute as fb_execute
from tradecraft.adapters.firebase_probe import parse as fb_parse
from tradecraft.adapters.firebase_probe.execute import USER_AGENT
from tradecraft.tools.firebase_probe import FirebaseProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS

# Realtime Database: a public-read instance returns the JSON tree (here, a
# small object), a locked instance returns 401 with an error body.
RTDB_OPEN_BODY = '{\n  "users": {\n    "u1": {\n      "email": "ops@examplecorp.example"\n    }\n  }\n}'
RTDB_LOCKED_BODY = '{\n  "error" : "Permission denied"\n}'

# Firestore documents.list on an open database returns a documents array;
# an empty collection returns just {}.
FIRESTORE_OPEN_BODY = (
    '{"documents":[{"name":"projects/examplecorp-prod/databases/(default)/documents/config/app",'
    '"fields":{"apiUrl":{"stringValue":"https://api.examplecorp.example"}},'
    '"createTime":"2024-03-02T10:11:12.345678Z","updateTime":"2024-03-02T10:11:12.345678Z"}]}'
)
FIRESTORE_LOCKED_BODY = (
    '{"error":{"code":403,"message":"Missing or insufficient permissions.",'
    '"status":"PERMISSION_DENIED"}}'
)
FIRESTORE_NOT_FOUND_BODY = (
    '{"error":{"code":404,"message":"Project examplecorp-nope does not exist.",'
    '"status":"NOT_FOUND"}}'
)


def _resp(status: int, text: str = ""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


def _route(rtdb: dict, firestore: dict):
    """Returns a fake requests.get keyed by project id and datastore."""
    def fake_get(url, **kwargs):
        if "firebaseio.com" in url:
            project = url.split("//", 1)[1].split("-default-rtdb", 1)[0]
            entry = rtdb[project]
        else:
            project = url.split("/projects/", 1)[1].split("/databases/", 1)[0]
            entry = firestore[project]
        if isinstance(entry, Exception):
            raise entry
        return entry
    return fake_get


# --- exact request shape ------------------------------------------------------

def test_rtdb_and_firestore_urls_headers_and_read_only_verbs():
    with patch.object(fb_execute.requests, "get", return_value=_resp(401, RTDB_LOCKED_BODY)) as get, \
         patch.object(fb_execute.requests, "post") as post, \
         patch.object(fb_execute.requests, "put") as put, \
         patch.object(fb_execute.requests, "patch") as patch_, \
         patch.object(fb_execute.requests, "delete") as delete:
        fb_execute.execute("examplecorp", timeout=6)

    assert [c.args[0] for c in get.call_args_list] == [
        "https://examplecorp-default-rtdb.firebaseio.com/.json?print=pretty&limitToFirst=5",
        "https://firestore.googleapis.com/v1/projects/examplecorp/databases/(default)/documents",
    ]
    for c in get.call_args_list:
        assert c.kwargs == {"headers": {"User-Agent": USER_AGENT}, "timeout": 6, "verify": False}
    post.assert_not_called()
    put.assert_not_called()
    patch_.assert_not_called()
    delete.assert_not_called()


# --- classification -----------------------------------------------------------

def test_open_rtdb_and_open_firestore_are_both_readable_with_snippet():
    rtdb = {"examplecorp-prod": _resp(200, RTDB_OPEN_BODY)}
    fs = {"examplecorp-prod": _resp(200, FIRESTORE_OPEN_BODY)}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp-prod")
    c = raw.checks[0]
    assert c.rtdb_status == 200 and c.rtdb_readable is True
    assert c.rtdb_body_snippet == RTDB_OPEN_BODY[:500]
    assert c.firestore_status == 200 and c.firestore_readable is True


def test_rtdb_null_body_is_not_readable():
    rtdb = {"examplecorp": _resp(200, "null")}
    fs = {"examplecorp": _resp(403, FIRESTORE_LOCKED_BODY)}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp")
    c = raw.checks[0]
    assert c.rtdb_status == 200 and c.rtdb_readable is False
    assert c.rtdb_body_snippet == ""


def test_locked_rtdb_and_locked_firestore_are_not_exposed():
    rtdb = {"examplecorp": _resp(401, RTDB_LOCKED_BODY)}
    fs = {"examplecorp": _resp(403, FIRESTORE_LOCKED_BODY)}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp")
    c = raw.checks[0]
    assert (c.rtdb_status, c.rtdb_readable) == (401, False)
    assert (c.firestore_status, c.firestore_readable) == (403, False)
    out = fb_parse.parse_firebase_result(raw)
    assert "exposed_projects" not in out
    assert out["reason"].startswith("no candidate project")


def test_firestore_only_exposure_is_reported():
    rtdb = {"examplecorp": requests.ConnectionError("Failed to resolve host")}
    fs = {"examplecorp": _resp(200, FIRESTORE_OPEN_BODY)}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp")
    c = raw.checks[0]
    assert c.rtdb_status is None
    assert "Failed to resolve host" in c.error
    assert c.firestore_readable is True
    out = fb_parse.parse_firebase_result(raw)
    assert out["exposed_projects"][0]["rtdb_readable"] is False
    assert out["exposed_projects"][0]["firestore_readable"] is True


def test_nonexistent_project_is_recorded_per_check_not_top_level():
    rtdb = {
        "examplecorp-nope": requests.ConnectionError("Failed to resolve host"),
        "examplecorp-prod": _resp(401, RTDB_LOCKED_BODY),
    }
    fs = {
        "examplecorp-nope": _resp(404, FIRESTORE_NOT_FOUND_BODY),
        "examplecorp-prod": _resp(403, FIRESTORE_LOCKED_BODY),
    }
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp-nope,examplecorp-prod")
    assert raw.error is None
    assert len(raw.checks) == 2
    assert raw.checks[0].firestore_status == 404
    assert raw.checks[0].error is not None


def test_firestore_200_with_non_json_body_is_not_readable():
    rtdb = {"examplecorp": _resp(404, "")}
    fs = {"examplecorp": _resp(200, "<html>proxy login</html>")}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp")
    c = raw.checks[0]
    assert c.firestore_readable is False
    assert c.error == "Firestore: HTTP 200 with a non-JSON body"


def test_request_exception_on_one_candidate_does_not_stop_loop():
    rtdb = {
        "boom": requests.Timeout("timed out"),
        "examplecorp": _resp(200, RTDB_OPEN_BODY),
    }
    fs = {
        "boom": requests.Timeout("timed out"),
        "examplecorp": _resp(403, FIRESTORE_LOCKED_BODY),
    }
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("boom,examplecorp")
    assert len(raw.checks) == 2
    assert raw.checks[1].rtdb_readable is True


# --- top-level and parser -----------------------------------------------------

def test_empty_candidates_is_top_level_error():
    raw = fb_execute.execute(" , ")
    assert raw.error == "no project IDs given"
    assert fb_parse.parse_firebase_result(raw) == {"error": "no project IDs given"}


def test_parse_exposed_projects_exact_shape():
    rtdb = {"examplecorp-prod": _resp(200, RTDB_OPEN_BODY)}
    fs = {"examplecorp-prod": _resp(200, FIRESTORE_OPEN_BODY)}
    with patch.object(fb_execute.requests, "get", side_effect=_route(rtdb, fs)):
        raw = fb_execute.execute("examplecorp-prod")
    out = fb_parse.parse_firebase_result(raw)
    assert out == {
        "exposed_projects": [
            {
                "project_id": "examplecorp-prod",
                "rtdb_readable": True,
                "rtdb_status": 200,
                "rtdb_body_snippet": RTDB_OPEN_BODY[:500],
                "firestore_readable": True,
                "firestore_status": 200,
            }
        ]
    }


# --- Tool wrapper + contract --------------------------------------------------

def test_tool_wrapper_end_to_end():
    with patch.object(fb_execute.requests, "get", side_effect=lambda url, **kw: _resp(
        200, RTDB_OPEN_BODY) if "firebaseio" in url else _resp(403, FIRESTORE_LOCKED_BODY)):
        out = FirebaseProbe()(project_ids="examplecorp")
    assert out["exposed_projects"][0]["project_id"] == "examplecorp"


def test_contract_is_non_destructive_cloud_only():
    tool = FirebaseProbe()
    assert tool.tool_id == "firebase_probe"
    assert tool.destructive is False
    assert tool.scope_param == "project_ids"
    assert tool.required_binary is None
    assert tool.spec.parameters["required"] == ["project_ids"]
    assert "firebase_probe" in load_profile("cloud")
    assert "firebase_probe" not in load_profile("web")
    assert any(t.tool_id == "firebase_probe" for t in ALL_TOOLS)
