"""
Raw execution for dork_search_probe: one GET to Google's Custom Search
JSON API with the model-supplied dork query (verbatim -- the model builds
its own site:/filetype:/inurl:/intitle: operators, mirroring gitdorker's
own free-text 'query' parameter). Requires GOOGLE_CSE_API_KEY and
GOOGLE_CSE_CX environment variables (an operator-configured Google Custom
Search Engine scoped to search the whole web, not just one site). No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

GOOGLE_CSE_URL = "https://www.googleapis.com/customsearch/v1"
MAX_RESULTS = 10


@dataclass
class RawDorkResult:
    query: str = ""
    items: List[Dict] = field(default_factory=list)
    total_results_reported: Optional[str] = None
    error: Optional[str] = None


def execute(query: str, num_results: int = 10, timeout: int = 10) -> RawDorkResult:
    q = (query or "").strip()
    if not q:
        return RawDorkResult(error="empty query")

    api_key = os.environ.get("GOOGLE_CSE_API_KEY")
    cx = os.environ.get("GOOGLE_CSE_CX")
    if not api_key or not api_key.strip():
        return RawDorkResult(query=q, error="GOOGLE_CSE_API_KEY environment variable not set")
    if not cx or not cx.strip():
        return RawDorkResult(query=q, error="GOOGLE_CSE_CX environment variable not set")

    if requests is None:
        return RawDorkResult(query=q, error="requests library not available")

    count = max(1, min(int(num_results or 10), MAX_RESULTS))

    try:
        resp = requests.get(
            GOOGLE_CSE_URL,
            params={"key": api_key.strip(), "cx": cx.strip(), "q": q, "num": count},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return RawDorkResult(query=q, error=f"request failed: {exc}")

    if resp.status_code != 200:
        return RawDorkResult(query=q, error=f"Google CSE API returned HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        data = resp.json()
    except ValueError:
        return RawDorkResult(query=q, error="Google CSE API returned a non-JSON body")

    result = RawDorkResult(query=q)
    result.items = data.get("items", []) or []
    search_info = data.get("searchInformation", {})
    result.total_results_reported = search_info.get("totalResults")
    return result
