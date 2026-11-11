"""HTTP request adapter using curl for custom requests, API testing, and PoC verification."""
from tradecraft.adapters.http_request.execute import (
    ALLOWED_METHODS,
    DEFAULT_TIMEOUT,
    build_argv,
    execute,
    execute_unchecked,
    normalize_target_url,
)
from tradecraft.adapters.http_request.parse import (
    host_port_from_url,
    parse_curl_headers,
    parse_http_response,
)

__all__ = [
    "ALLOWED_METHODS",
    "DEFAULT_TIMEOUT",
    "build_argv",
    "execute",
    "execute_unchecked",
    "host_port_from_url",
    "normalize_target_url",
    "parse_curl_headers",
    "parse_http_response",
]
