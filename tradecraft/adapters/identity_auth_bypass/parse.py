"""
Pure parsing logic for the identity-endpoint auth-bypass check.
No I/O here -- see execute.py.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Common "current user / identity" endpoints. The model can prepend one
# more explicit path via the tool's `test_path` parameter.
IDENTITY_PATHS: List[str] = [
    "/api/me",
    "/api/user",
    "/api/users/me",
    "/api/profile",
    "/api/v1/me",
    "/api/v1/user",
    "/api/v1/profile",
    "/rest/user/whoami",
    "/user",
    "/me",
    "/account",
    "/api/account",
    "/profile",
]

# Hard cap on how many identity paths one call may probe (each probe is
# two HTTP requests). Equal to the full default list, so an explicit
# test_path plus the defaults is cut to this length.
MAX_CANDIDATE_PATHS = 13


def normalize_base_url(target: str) -> str:
    """Bare host -> https://host. Trailing slash stripped. Empty -> ''.
    Scheme detection is case-insensitive (e.g. 'HTTPS://host' is
    recognized as already schemed) so a mixed-case scheme is never
    double-prefixed into a malformed URL like 'https://HTTPS://host'."""
    t = (target or "").strip().rstrip("/")
    if not t:
        return ""
    lowered = t.lower()
    if not lowered.startswith("http://") and not lowered.startswith("https://"):
        t = f"https://{t}"
    return t


def candidate_paths(test_path: str = "") -> List[str]:
    """Explicit test_path first (if given), then the default identity
    paths, de-duplicated and capped at MAX_CANDIDATE_PATHS."""
    paths: List[str] = []
    explicit = (test_path or "").strip()
    if explicit:
        if not explicit.startswith("/"):
            explicit = "/" + explicit
        paths.append(explicit)
    for p in IDENTITY_PATHS:
        if p not in paths:
            paths.append(p)
    return paths[:MAX_CANDIDATE_PATHS]


def parse_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Turn execute()'s raw dict into the model-facing result.

    A hit is a path where the unauthenticated baseline was rejected
    (401/403) and the forged alg=none token was accepted (200). The first
    hit ends probing (see execute.py), so at most one hit is reported.
    """
    target = raw.get("target", "")
    if raw.get("error") and not raw.get("probes"):
        return {"target": target, "vulnerable": False, "probes_sent": 0, "error": raw["error"]}

    probes: List[Dict[str, Any]] = raw.get("probes", [])
    hit: Optional[Dict[str, Any]] = next(
        (p for p in probes if p["baseline_status"] in (401, 403) and p["forged_status"] == 200),
        None,
    )
    result: Dict[str, Any] = {
        "target": target,
        "vulnerable": hit is not None,
        "probes_sent": len(probes),
    }
    if raw.get("error"):
        result["error"] = raw["error"]
    if hit is not None:
        result.update({
            "technique": "none_algorithm_forgery",
            "identity_url": hit["url"],
            "baseline_status": hit["baseline_status"],
            "forged_status": hit["forged_status"],
            "forged_token": raw.get("forged_token"),
        })
    return result
