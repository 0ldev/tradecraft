"""
Execution logic for model-directed headless browser actions via Playwright.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional, Set, Tuple

XSS_PROBE_PAYLOAD = "<b>rsxssprobe</b>"
MAX_POST_DATA_CHARS = 2000
_IGNORED_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "cache-control",
    "connection", "content-length", "host", "origin", "pragma", "referer",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "user-agent",
})


@dataclass
class RawPlaywrightResult:
    dom_findings: List[Dict[str, Any]] = field(default_factory=list)
    storage_keys: List[Dict[str, str]] = field(default_factory=list)
    requests: List[Dict[str, Any]] = field(default_factory=list)
    screenshot_png: Optional[bytes] = None
    final_url: Optional[str] = None
    error: Optional[str] = None


def execute(
    target_url: str,
    actions: List[Dict[str, Any]],
    probe_xss: bool = False,
    timeout_seconds: int = 60,
) -> RawPlaywrightResult:
    """Drives a headless Chromium browser through explicit model-chosen actions."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return RawPlaywrightResult(error="playwright package is not installed")

    result = RawPlaywrightResult()
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

                for action in actions:
                    act_type = action.get("action")
                    if act_type == "click":
                        _dismiss_overlay()
                        selector = action.get("selector", "")
                        if selector:
                            page.click(selector)
                    elif act_type == "fill":
                        selector = action.get("selector", "")
                        value = str(action.get("value", ""))
                        if selector:
                            page.fill(selector, value)
                    elif act_type == "fill_first_match":
                        selector = action.get(
                            "selector",
                            "input[type=text], input[type=search], input:not([type]), textarea",
                        )
                        reveal_selector = action.get(
                            "reveal_selector",
                            '[aria-label*="search" i], button[class*="search" i], a[class*="search" i]',
                        )
                        value = str(action.get("value", ""))

                        def _fill_first_visible():
                            for el in page.query_selector_all(selector):
                                try:
                                    if not el.is_visible():
                                        continue
                                    el.fill(value)
                                    if action.get("submit"):
                                        el.press("Enter")
                                    return True
                                except Exception:
                                    continue
                            return False

                        if not _fill_first_visible():
                            for toggle in page.query_selector_all(reveal_selector):
                                try:
                                    if not toggle.is_visible():
                                        continue
                                    _dismiss_overlay()
                                    toggle.click()
                                    page.wait_for_timeout(500)
                                except Exception:
                                    continue
                                if _fill_first_visible():
                                    break
                    elif act_type == "wait":
                        wait_ms = int(action.get("value", 1000))
                        page.wait_for_timeout(max(50, min(wait_ms, 15000)))
                    elif act_type == "navigate":
                        nav_url = action.get("url")
                        if nav_url:
                            page.goto(nav_url)

                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass

                # Extra 500ms wait for reactive change-detection / rendering pass
                page.wait_for_timeout(500)
                result.final_url = page.url
                result.requests = requests_list

                if probe_xss:
                    inner_html = page.evaluate("document.body.innerHTML") or ""
                    inner_lower = inner_html.lower()
                    if (
                        "<script>alert" in inner_lower
                        or "javascript:alert" in inner_lower
                        or XSS_PROBE_PAYLOAD.lower() in inner_lower
                    ):
                        result.dom_findings.append({
                            "path": page.url,
                            "sink_type": "innerHTML",
                            "payload": XSS_PROBE_PAYLOAD,
                        })

                # Storage key names only (never values)
                try:
                    local_keys = page.evaluate("Object.keys(localStorage)") or []
                    for k in local_keys:
                        result.storage_keys.append({"storage_type": "localStorage", "key_name": str(k)})
                except Exception:
                    pass

                try:
                    session_keys = page.evaluate("Object.keys(sessionStorage)") or []
                    for k in session_keys:
                        result.storage_keys.append({"storage_type": "sessionStorage", "key_name": str(k)})
                except Exception:
                    pass

                # Capture full-page screenshot
                try:
                    result.screenshot_png = page.screenshot(full_page=True)
                except Exception:
                    pass

            finally:
                browser.close()

    except Exception as exc:
        result.error = str(exc)

    return result
