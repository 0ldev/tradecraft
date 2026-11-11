"""
Pure parsing for host_header_injection_probe: checks whether a candidate
header's marker domain was reflected into an absolute-URL-shaped context
(a Location redirect, a link, a canonical tag) rather than just echoed
as plain text somewhere incidental. No I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.host_header_injection_probe.execute import RawHeaderAttempt, RawHostHeaderResult


def _reflected_in_absolute_url(marker: str, location: str, body: str) -> bool:
    if marker in location:
        return True
    # Only count a body reflection if the marker sits inside an
    # absolute-URL-shaped string (http(s)://...marker...), e.g. a
    # password-reset link or a <link rel="canonical"> tag -- a marker
    # appearing as plain incidental text is not exploitable.
    pattern = re.compile(r"https?://[^\s\"'<>]*" + re.escape(marker))
    return bool(pattern.search(body))


def parse(raw: RawHostHeaderResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    results: List[Dict[str, Any]] = []
    reflected_headers: List[str] = []

    for attempt in raw.attempts:
        if attempt.error:
            results.append({"header": attempt.header, "classification": "network_error", "error": attempt.error})
            continue

        reflected = _reflected_in_absolute_url(attempt.marker_domain, attempt.location, attempt.body)
        if reflected:
            reflected_headers.append(attempt.header)

        results.append({
            "header": attempt.header,
            "marker_domain": attempt.marker_domain,
            "status_code": attempt.status_code,
            "reflected_in_absolute_url": reflected,
            "location": attempt.location or None,
        })

    vulnerable = bool(reflected_headers)
    summary = (
        f"Marker domain reflected into an absolute-URL context via: {', '.join(reflected_headers)}. "
        "This is purely observational -- no email was sent or assumed; the finding is that the "
        "application trusts a client-supplied header when building absolute links."
        if vulnerable else
        f"Tested {len(raw.attempts)} header(s); no marker domain was reflected into an absolute-URL context."
    )

    return {
        "target": raw.target,
        "method": raw.method,
        "headers_tested": len(raw.attempts),
        "vulnerable": vulnerable,
        "reflected_headers": reflected_headers,
        "summary": summary,
        "attempts": results,
    }
