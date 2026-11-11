"""
Sends a minimal GraphQL introspection query to a URL via POST.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
}


@dataclass
class RawGraphqlResult:
    status_code: int = 0
    body: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def execute(url: str, timeout: int = 10) -> RawGraphqlResult:
    """requests.post(url, json=INTROSPECTION_QUERY, timeout=timeout).
    RawGraphqlResult{status_code, body: dict | None (parsed JSON),
    error: str | None (set only on a request exception, not on a normal
    GraphQL error-shaped response)}."""
    clean_url = url.strip()
    if not clean_url:
        return RawGraphqlResult(error="empty URL")
    try:
        resp = requests.post(
            clean_url,
            json=INTROSPECTION_QUERY,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
        )
        try:
            body = resp.json() if resp.text else None
        except Exception:
            body = None
        return RawGraphqlResult(status_code=resp.status_code, body=body, error=None)
    except requests.RequestException as exc:
        return RawGraphqlResult(error=str(exc))
