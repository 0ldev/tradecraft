"""
Raw execution for http_write_request: the state-mutating (PUT/DELETE/PATCH)
counterpart to tradecraft/adapters/http_request/execute.py. Reuses that
module's `build_argv`/`normalize_target_url` and its `execute_unchecked`
(the actual curl subprocess call, with no method allowlist of its own) so
the two tools don't carry two copies of the same subprocess logic -- only
the allowlist differs, and each module owns its own disjoint one.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from tradecraft.adapters.http_request.execute import (
    DEFAULT_TIMEOUT,
    build_argv,
    execute_unchecked,
    normalize_target_url,
)

# http_write_request exists only for methods that create or remove real,
# persistent state on the target and don't undo themselves -- see
# docs/policy.md. GET/HEAD/OPTIONS/POST (including non-destructive POST
# probing, e.g. a login-form test) belong to the always-available
# http_request instead; this tool rejects them.
WRITE_METHODS = {"PUT", "DELETE", "PATCH"}


def execute(
    url: str,
    method: str,
    headers: Optional[str] = None,
    data: Optional[str] = None,
    follow_redirects: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    binary: str = "curl",
) -> Dict[str, Any]:
    http_method = (method or "").strip().upper()
    if http_method not in WRITE_METHODS:
        return {
            "url": normalize_target_url(url),
            "method": http_method or "(missing)",
            "error": (
                f"method must be one of {sorted(WRITE_METHODS)} -- "
                "http_write_request only performs state-mutating writes/deletes. "
                "Use http_request for GET, HEAD, OPTIONS, or POST."
            ),
        }
    return execute_unchecked(
        url=url, method=http_method, headers=headers, data=data,
        follow_redirects=follow_redirects, timeout=timeout, binary=binary,
    )


__all__ = ["DEFAULT_TIMEOUT", "WRITE_METHODS", "build_argv", "execute", "normalize_target_url"]
