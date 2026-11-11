"""State-mutating (PUT/DELETE/PATCH) HTTP request adapter -- the destructive
counterpart to tradecraft/adapters/http_request/. See execute.py's WRITE_METHODS
allowlist and config/tools/http_write_request.yaml for the model-facing
contract."""
from tradecraft.adapters.http_write_request.execute import (
    DEFAULT_TIMEOUT,
    WRITE_METHODS,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.http_write_request.parse import (
    host_port_from_url,
    parse_curl_headers,
    parse_http_response,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "WRITE_METHODS",
    "build_argv",
    "execute",
    "host_port_from_url",
    "normalize_target_url",
    "parse_curl_headers",
    "parse_http_response",
]
