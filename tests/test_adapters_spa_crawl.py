import json
import sys
from unittest.mock import MagicMock, patch

from tradecraft.adapters.spa_crawl.execute import (
    MARKER,
    RawSpaCrawlResult,
    execute,
)
from tradecraft.adapters.spa_crawl.parse import parse_result


def test_parse_result_clean():
    raw = RawSpaCrawlResult(
        final_url="https://example.com/spa",
        requests=[
            {"method": "GET", "url": "https://example.com/api/init"},
            {"method": "POST", "url": "https://example.com/api/search", "json_params": ["q"]},
        ],
    )
    parsed = parse_result(raw)
    assert parsed["final_url"] == "https://example.com/spa"
    assert parsed["total_requests"] == 2
    assert len(parsed["requests"]) == 2
    assert parsed["requests"][1]["json_params"] == ["q"]
    assert "error" not in parsed


def test_parse_result_with_error():
    raw = RawSpaCrawlResult(
        error="Target unreachable",
    )
    parsed = parse_result(raw)
    assert parsed["error"] == "Target unreachable"


def test_execute_missing_playwright():
    with patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}):
        res = execute("https://example.com")
        assert res.error is not None
        assert "playwright package is not installed" in res.error


def test_execute_mocked_interaction():
    mock_page = MagicMock()
    mock_page.url = "https://example.com/spa/home"

    # Simulate request event handler registration
    registered_handlers = {}

    def fake_on(event, handler):
        registered_handlers[event] = handler

    mock_page.on.side_effect = fake_on

    # Mock elements to fill
    el1 = MagicMock()
    el1.is_visible.return_value = True
    el1.is_enabled.return_value = True

    el2 = MagicMock()
    el2.is_visible.return_value = False  # Should be skipped

    mock_page.query_selector_all.return_value = [el1, el2]

    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context

    mock_p = MagicMock()
    mock_p.chromium.launch.return_value = mock_browser

    mock_sync_pw = MagicMock()
    mock_sync_pw.return_value.__enter__.return_value = mock_p

    def run_with_events():
        with patch("playwright.sync_api.sync_playwright", mock_sync_pw):
            def trigger_requests(*args, **kwargs):
                handler = registered_handlers.get("request")
                if handler:
                    req_get = MagicMock()
                    req_get.method = "GET"
                    req_get.url = "https://example.com/api/config"
                    req_get.post_data = None
                    handler(req_get)

                    req_post = MagicMock()
                    req_post.method = "POST"
                    req_post.url = "https://example.com/api/query"
                    req_post.headers = {
                        "user-agent": "Mozilla/5.0",
                        "x-csrf-token": "csrf123",
                    }
                    req_post.post_data = json.dumps({"search_query": "test", "page": 1})
                    handler(req_post)

            mock_page.goto.side_effect = trigger_requests
            return execute("https://example.com/spa", timeout_seconds=20)

    res = run_with_events()

    assert res.error is None
    assert res.final_url == "https://example.com/spa/home"
    assert len(res.requests) == 2
    assert res.requests[0]["method"] == "GET"
    assert res.requests[1]["method"] == "POST"
    assert res.requests[1]["headers"] == {"x-csrf-token": "csrf123"}
    assert res.requests[1]["post_data"] == json.dumps({"search_query": "test", "page": 1})
    assert res.requests[1]["json_params"] == ["page", "search_query"]

    # Verify input element interaction
    el1.fill.assert_called_once_with(MARKER)
    el1.press.assert_called_once_with("Enter")
    el2.fill.assert_not_called()
    mock_browser.close.assert_called_once()
