"""
Execution logic for automated generic SPA interaction discovery via Playwright.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

MARKER = "rsspacrawlprobe"
MAX_INPUTS = 6
MAX_POST_DATA_CHARS = 2000
INPUT_SELECTOR = "input[type=text], input[type=search], input:not([type]), textarea"
_IGNORED_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "cache-control",
    "connection", "content-length", "host", "origin", "pragma", "referer",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "user-agent",
})


@dataclass
class RawSpaCrawlResult:
    requests: List[Dict[str, Any]] = field(default_factory=list)
    final_url: Optional[str] = None
    error: Optional[str] = None


def execute(target_url: str, timeout_seconds: int = 45) -> RawSpaCrawlResult:
    """Loads a URL and automatically fills visible text inputs to discover SPA API requests."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return RawSpaCrawlResult(error="playwright package is not installed")

    result = RawSpaCrawlResult()
    requests_list: List[Dict[str, Any]] = []
    seen_requests: Set[Tuple[str, str]] = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(min(30000, max(5000, timeout_seconds * 1000)))

                def on_request(req):
                    try:
                        method = req.method
                        url = req.url
                        key = (method, url)
                        if key in seen_requests:
                            return
                        seen_requests.add(key)

                        entry: Dict[str, Any] = {"method": method, "url": url}
                        raw_headers = getattr(req, "headers", None)
                        if isinstance(raw_headers, dict):
                            custom_headers = {
                                k: v for k, v in raw_headers.items()
                                if k.lower() not in _IGNORED_HEADERS
                            }
                            if custom_headers:
                                entry["headers"] = custom_headers
                        if method in ("POST", "PUT", "PATCH"):
                            post_data = req.post_data
                            if isinstance(post_data, str) and post_data:
                                entry["post_data"] = post_data[:MAX_POST_DATA_CHARS]
                                try:
                                    parsed_body = json.loads(post_data)
                                    if isinstance(parsed_body, dict):
                                        entry["json_params"] = sorted(list(parsed_body.keys()))
                                except Exception:
                                    pass
                        requests_list.append(entry)
                    except Exception:
                        pass

                page.on("request", on_request)

                page.goto(target_url)

                def _dismiss_overlay():
                    try:
                        page.keyboard.press("Escape")
                        page.wait_for_timeout(300)
                    except Exception:
                        pass

                _dismiss_overlay()

                matching_elements = page.query_selector_all(INPUT_SELECTOR)
                filled_count = 0
                for el in matching_elements:
                    if filled_count >= MAX_INPUTS:
                        break
                    try:
                        if not el.is_visible() or not el.is_enabled():
                            continue
                        _dismiss_overlay()
                        el.fill(MARKER)
                        el.press("Enter")
                        filled_count += 1
                        page.wait_for_timeout(500)
                    except Exception:
                        continue

                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                result.final_url = page.url
                result.requests = requests_list

            finally:
                browser.close()

    except Exception as exc:
        result.error = str(exc)

    return result
