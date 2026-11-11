"""
Unit tests for webshell_upload adapter and tool layer.
All HTTP is mocked via an injected session; no live requests.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import requests

from tradecraft.adapters.webshell_upload import execute as ws_execute
from tradecraft.adapters.webshell_upload import parse as ws_parse
from tradecraft.tools.webshell_upload import WebshellUpload

UPLOAD_PAGE = """
<html><body>
  <form action="/profile/avatar" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="tok123">
    <input type="file" name="avatar">
    <input type="submit" value="Upload">
  </form>
</body></html>
"""

NO_FORM_PAGE = "<html><body><p>Welcome</p></body></html>"


def _resp(status: int, text: str = ""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


def test_find_upload_form_extracts_action_file_field_and_hidden():
    form = ws_parse.find_upload_form(UPLOAD_PAGE, "https://target.test/profile")
    assert form is not None
    assert form.action_url == "https://target.test/profile/avatar"
    assert form.file_field == "avatar"
    assert form.hidden == {"csrf": "tok123"}


def test_find_upload_form_none_when_no_file_input():
    assert ws_parse.find_upload_form(NO_FORM_PAGE, "https://target.test") is None
    assert ws_parse.find_upload_form("", "https://target.test") is None


def test_extract_upload_path_from_echoed_json_line_and_fallback():
    body = '{"ok": true, "url": "/static/up/shell.phtml"}'
    assert ws_parse.extract_upload_path(body, "shell.phtml") == "/static/up/shell.phtml"
    assert ws_parse.extract_upload_path("saved shell.php", "shell.php") == "/uploads/shell.php"


def test_execution_confirmed_requires_real_command_output():
    assert ws_parse.execution_confirmed(200, "uid=33(www-data) gid=33")
    assert not ws_parse.execution_confirmed(200, "shell.php")
    assert not ws_parse.execution_confirmed(404, "uid=0")


def test_plant_on_second_bypass_reports_path_loudly():
    session = MagicMock()
    # GET target -> upload form; POSTs: first variant rejected (415), second accepted & echoed
    session.get.side_effect = [
        _resp(200, UPLOAD_PAGE),  # page fetch
        _resp(200, "uid=33(www-data) gid=33(www-data)"),  # execution probe
    ]
    session.post.side_effect = [
        _resp(415, "bad type"),
        _resp(200, '{"path": "/uploads/shell.php5"}'),
    ]
    raw = ws_execute.execute("https://target.test/profile", session=session)
    assert raw["planted"] is True
    assert raw["bypass_used"] == ".php5"
    assert raw["planted_path"] == "/uploads/shell.php5"
    assert raw["upload_attempts"] == 2

    # The upload POST carried the hidden csrf field and the file under the discovered name
    post_kwargs = session.post.call_args_list[0].kwargs
    assert post_kwargs["data"] == {"csrf": "tok123"}
    assert "avatar" in post_kwargs["files"]

    parsed = ws_parse.parse_result(raw)
    assert parsed["planted"] is True
    assert parsed["cleanup_required"] is True
    assert parsed["planted_path"] == "/uploads/shell.php5"
    assert "WEBSHELL PLANTED" in parsed["ALERT"]
    assert "/uploads/shell.php5" in parsed["ALERT"]
    assert "log_finding" in parsed["ALERT"]


def test_accepted_but_not_executed_is_reported_for_cleanup_and_continues():
    session = MagicMock()
    session.get.side_effect = [
        _resp(200, UPLOAD_PAGE),
        _resp(404, ""),  # trigger for variant 1 fails
        _resp(200, "no output"),  # trigger for variant 2 gives no uid
    ] + [_resp(200, "")] * 10
    # Each POST echoes its own filename back, so all six uploads count as accepted
    def echo_post(url, data=None, files=None, headers=None, timeout=None, verify=None):
        filename = next(iter(files.values()))[0]
        return _resp(200, f"/uploads/{filename}")

    session.post.side_effect = echo_post
    raw = ws_execute.execute("https://target.test/profile", session=session)
    parsed = ws_parse.parse_result(raw)
    assert parsed["planted"] is False
    assert len(parsed["accepted_uploads"]) == 6
    assert parsed["cleanup_required"] is True
    assert "ALERT" not in parsed


def test_upload_attempts_hard_capped_at_six_posts():
    session = MagicMock()
    session.get.side_effect = [_resp(200, UPLOAD_PAGE)] + [_resp(404, "")] * 50
    session.post.return_value = _resp(415, "rejected")
    raw = ws_execute.execute("https://target.test/profile", session=session)
    assert session.post.call_count == ws_parse.MAX_UPLOAD_ATTEMPTS == 6
    assert raw["upload_attempts"] == 6
    assert raw["planted"] is False


def test_no_form_falls_back_to_posting_target_directly():
    session = MagicMock()
    session.get.side_effect = [_resp(200, NO_FORM_PAGE)]
    session.post.return_value = _resp(415, "")
    ws_execute.execute("https://target.test/upload", session=session)
    assert session.post.call_args_list[0].args[0] == "https://target.test/upload"
    assert "file" in session.post.call_args_list[0].kwargs["files"]


def test_page_fetch_failure_returns_error_without_posting():
    session = MagicMock(spec=requests.Session)
    session.get.side_effect = requests.ConnectionError("refused")
    raw = ws_execute.execute("https://target.test", session=session)
    assert raw["planted"] is False
    assert "page fetch failed" in raw["error"]
    session.post.assert_not_called()


def test_tool_run_facts_and_evidence(monkeypatch):
    session = MagicMock()
    session.get.side_effect = [_resp(200, UPLOAD_PAGE), _resp(200, "uid=0(root)")]
    session.post.return_value = _resp(200, "/uploads/shell.php")
    original = ws_execute.execute
    monkeypatch.setattr(ws_execute, "execute", lambda **kw: original(session=session, **kw))

    tool = WebshellUpload()
    params = {"target": "https://target.test/profile"}
    result = tool.run(**params)
    assert result["planted"] is True
    assert result["planted_path"] == "/uploads/shell.php"
    assert "ALERT" in result

    facts = tool.extract_facts(params, result)
    assert facts == [{"host": "target.test", "port": 443, "webshell_planted": "/uploads/shell.php"}]

    host, data = tool.extract_evidence(params, result)
    assert host == "target.test"
    assert data["planted_url"] == "https://target.test/uploads/shell.php"
    assert "_full_evidence" not in result


def test_tool_no_facts_when_not_planted(monkeypatch):
    session = MagicMock()
    session.get.side_effect = [_resp(200, NO_FORM_PAGE)]
    session.post.return_value = _resp(415, "")
    original = ws_execute.execute
    monkeypatch.setattr(ws_execute, "execute", lambda **kw: original(session=session, **kw))
    tool = WebshellUpload()
    params = {"target": "https://target.test"}
    result = tool.run(**params)
    assert result["planted"] is False
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None
