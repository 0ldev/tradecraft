"""
Parsing for http_write_request. A PUT/DELETE/PATCH response's shape (status
line, headers, body) is parsed identically to any other curl response, so
this re-exports tradecraft/adapters/http_request/parse.py's pure functions
rather than duplicating them -- there is no write-specific parsing to add.
"""
from __future__ import annotations

from tradecraft.adapters.http_request.parse import (
    DEFAULT_MAX_BODY_CHARS,
    evidence_target_from_url,
    host_port_from_url,
    parse_curl_headers,
    parse_http_response,
)

__all__ = [
    "DEFAULT_MAX_BODY_CHARS",
    "evidence_target_from_url",
    "host_port_from_url",
    "parse_curl_headers",
    "parse_http_response",
]
