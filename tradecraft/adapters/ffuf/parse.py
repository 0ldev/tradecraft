"""
Pure parsing: ffuf's JSON output -> structured list of discovered endpoints.
No subprocess, no I/O.
"""
from __future__ import annotations

import json
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.ffuf.execute import CanarySignature


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    target = target.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        # Prepend // so urlsplit treats it as netloc
        parsed = urllib.parse.urlsplit("//" + target)
        default_port = 80 if parsed.port == 80 else 443
    else:
        parsed = urllib.parse.urlsplit(target)
        default_port = 80 if parsed.scheme == "http" else 443

    host = parsed.hostname or target.split(":")[0].split("/")[0]
    port = parsed.port or default_port
    return host, port


def parse_results(
    json_output: str,
    canary: Optional[CanarySignature] = None,
) -> List[Dict[str, Any]]:
    """Parse ffuf JSON output and filter out phantom/canary endpoints."""
    if not json_output or not json_output.strip():
        return []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return []

    raw_results = data.get("results", [])
    if not raw_results:
        return []

    endpoints: List[Dict[str, Any]] = []
    for res in raw_results:
        input_data = res.get("input", {})
        fuzz_val = input_data.get("FUZZ", "")
        path = "/" + fuzz_val.lstrip("/")
        status = res.get("status", 0)
        length = res.get("length", 0)
        words = res.get("words", 0)
        lines = res.get("lines", 0)
        redirect = res.get("redirectlocation") or ""
        url = res.get("url") or ""

        # Canary filtering: drop uniform WAF/catch-all responses
        if canary is not None:
            # 1. Exact status and body length match
            if status == canary.status_code and length == canary.length:
                continue
            # 2. Catch-all redirect match
            if (
                status in (301, 302, 307, 308)
                and canary.redirect_location
                and redirect == canary.redirect_location
            ):
                continue

        ep: Dict[str, Any] = {
            "path": path,
            "status_code": status,
            "length": length,
            "words": words,
            "lines": lines,
        }
        if url:
            ep["url"] = url
        if redirect:
            ep["redirect_location"] = redirect
        endpoints.append(ep)

    # Phantom-endpoint discrimination: WAFs / CDNs often return uniform responses
    # that flood results with bogus endpoints sharing a single length.
    if len(endpoints) >= 8:
        lengths = [ep["length"] for ep in endpoints]
        if lengths and all(l > 0 for l in lengths):
            dominant_len, dominant_count = Counter(lengths).most_common(1)[0]
            if dominant_count / len(endpoints) >= 0.8:
                endpoints = [ep for ep in endpoints if ep["length"] != dominant_len]

    return endpoints
