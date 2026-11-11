"""
Execution logic for favicon_correlator: fetches favicon bytes and queries Shodan API.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
import urllib3

from tradecraft.adapters.favicon_correlator import parse as favicon_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SHODAN_FAVICON_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
FAVICON_FETCH_TIMEOUT = 10


@dataclass
class RawFaviconResult:
    favicon_hash: Optional[int] = None
    shodan_json: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def execute(target: str, api_key: str, timeout: int = 30) -> RawFaviconResult:
    target = target.strip()
    if not target:
        return RawFaviconResult(error="Target cannot be empty")

    api_key = api_key.strip()
    if not api_key:
        return RawFaviconResult(error="SHODAN_API_KEY cannot be empty")

    target_url = favicon_parse.normalize_target_url(target)
    favicon_url = urllib.parse.urljoin(target_url, "/favicon.ico")

    try:
        resp = requests.get(favicon_url, timeout=FAVICON_FETCH_TIMEOUT, verify=False)
    except requests.RequestException as exc:
        return RawFaviconResult(error=f"failed to fetch favicon from {favicon_url}: {exc}")

    if resp.status_code != 200 or not resp.content:
        return RawFaviconResult(
            error=f"no favicon at {favicon_url} (status {resp.status_code})"
        )

    favicon_hash = favicon_parse.compute_shodan_favicon_hash(resp.content)

    params = {
        "key": api_key,
        "query": f"http.favicon.hash:{favicon_hash}",
    }

    try:
        shodan_resp = requests.get(
            SHODAN_FAVICON_SEARCH_URL,
            params=params,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return RawFaviconResult(
            favicon_hash=favicon_hash,
            error=f"Shodan search request failed: {exc}",
        )

    if shodan_resp.status_code != 200:
        try:
            err_detail = shodan_resp.json().get("error") or shodan_resp.text[:200]
        except Exception:
            err_detail = shodan_resp.text[:200]
        return RawFaviconResult(
            favicon_hash=favicon_hash,
            error=f"Shodan API error (status {shodan_resp.status_code}): {err_detail}",
        )

    try:
        data = shodan_resp.json()
    except Exception as exc:
        return RawFaviconResult(
            favicon_hash=favicon_hash,
            error=f"failed to parse Shodan JSON response: {exc}",
        )

    return RawFaviconResult(favicon_hash=favicon_hash, shodan_json=data)
