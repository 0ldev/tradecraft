import sys
from unittest.mock import MagicMock, patch

from tradecraft.adapters.playwright_engine.execute import (
    RawPlaywrightResult,
    XSS_PROBE_PAYLOAD,
    execute,
)
from tradecraft.adapters.playwright_engine.parse import parse_result


def test_parse_result_clean():
    raw = RawPlaywrightResult(
        final_url="https://example.com/app",
        dom_findings=[],
        storage_keys=[{"storage_type": "localStorage", "key_name": "theme"}],
    )
    parsed = parse_result(raw)
    assert parsed["final_url"] == "https://example.com/app"
    assert parsed["dom_findings"] == []
    assert len(parsed["storage_keys"]) == 1
    assert parsed["storage_keys"][0]["key_name"] == "theme"
    assert "error" not in parsed


def test_parse_result_with_error():
    raw = RawPlaywrightResult(
        final_url=None,
        error="Navigation timeout",
    )
    parsed = parse_result(raw)
    assert parsed["error"] == "Navigation timeout"


def test_execute_missing_playwright():
    with patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}):
        res = execute("https://example.com", actions=[])
        assert res.error is not None
        assert "playwright package is not installed" in res.error


def test_execute_mocked_interaction():
    mock_page = MagicMock()
    mock_page.url = "https://example.com/dashboard"
    mock_page.evaluate.side_effect = [
        f"<div>{XSS_PROBE_PAYLOAD}</div>",  # innerHTML
        ["token_key", "pref_key"],          # localStorage
        ["session_id"],                    # sessionStorage
    ]
    mock_page.screenshot.return_value = b"\x89PNG\r\n\x1a\nscreenshotdata"

    registered_handlers = {}

    def fake_on(event, handler):
        registered_handlers[event] = handler

    mock_page.on.side_effect = fake_on

    def trigger_requests(*args, **kwargs):
        handler = registered_handlers.get("request")
        if handler:
            req_post = MagicMock()
            req_post.method = "POST"
            req_post.url = "https://example.com/api/v1/search"
            req_post.headers = {
                "user-agent": "Mozilla/5.0",
                "authorization": "Bearer eyJ123",
                "x-api-version": "2",
            }
            req_post.post_data = '{"query": "test search"}'
            handler(req_post)

    mock_page.goto.side_effect = trigger_requests

    mock_input_el = MagicMock()
    mock_input_el.is_visible.return_value = True
    mock_page.query_selector_all.return_value = [mock_input_el]

    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context

    mock_p = MagicMock()
    mock_p.chromium.launch.return_value = mock_browser

    mock_sync_pw = MagicMock()
    mock_sync_pw.return_value.__enter__.return_value = mock_p

    actions = [
        {"action": "fill_first_match", "value": "test search", "submit": True},
        {"action": "click", "selector": "#submit-btn"},
        {"action": "wait", "value": 100},
        {"action": "navigate", "url": "https://example.com/dashboard"},
    ]

    with patch("playwright.sync_api.sync_playwright", mock_sync_pw):
        res = execute(
            "https://example.com",
            actions=actions,
            probe_xss=True,
            timeout_seconds=30,
        )

    assert res.error is None
    assert res.final_url == "https://example.com/dashboard"
    assert len(res.dom_findings) == 1
    assert res.dom_findings[0]["payload"] == XSS_PROBE_PAYLOAD
    assert len(res.storage_keys) == 3
    assert len(res.requests) == 1
    assert res.requests[0]["method"] == "POST"
    assert res.requests[0]["url"] == "https://example.com/api/v1/search"
    assert res.requests[0]["headers"] == {
        "authorization": "Bearer eyJ123",
        "x-api-version": "2",
    }
    assert res.requests[0]["post_data"] == '{"query": "test search"}'
    assert res.requests[0]["json_params"] == ["query"]
    assert res.screenshot_png == b"\x89PNG\r\n\x1a\nscreenshotdata"
    mock_page.goto.assert_any_call("https://example.com")
    mock_page.goto.assert_any_call("https://example.com/dashboard")
    mock_page.click.assert_called_with("#submit-btn")
    mock_browser.close.assert_called_once()
