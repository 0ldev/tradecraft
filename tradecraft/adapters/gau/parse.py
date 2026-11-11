"""
Pure parsing functions for gau (GetAllURLs) passive reconnaissance output.
No I/O or subprocess logic here.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Set, Tuple

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
}


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_gau_output(stdout: str, base_domain: str = "") -> Dict[str, Any]:
    """Parses newline-delimited URLs from gau into structured lists of URLs,
    endpoints (filtering out static assets), subdomains, and parameters."""
    seen_urls: Set[str] = set()
    endpoints: Set[str] = set()
    subdomains: Set[str] = set()
    parameters: Set[str] = set()

    clean_base = base_domain.strip().lower()

    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("time="):
            continue

        url_str = line
        try:
            parsed = urllib.parse.urlsplit(url_str if "://" in url_str else f"http://{url_str}")
        except Exception:
            continue

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            continue

        seen_urls.add(url_str)

        if clean_base and (hostname == clean_base or hostname.endswith("." + clean_base)):
            subdomains.add(hostname)
        elif not clean_base:
            subdomains.add(hostname)

        path = parsed.path or "/"
        lower_path = path.lower()
        # Skip static binary/media assets
        if any(lower_path.endswith(ext) for ext in IGNORED_EXTENSIONS):
            continue

        endpoints.add(path)

        if parsed.query:
            try:
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                parameters.update(qs.keys())
            except Exception:
                pass

    return {
        "urls": sorted(seen_urls),
        "endpoints": sorted(endpoints),
        "subdomains": sorted(subdomains),
        "parameters": sorted(parameters),
        "total_urls": len(seen_urls),
        "total_endpoints": len(endpoints),
        "total_subdomains": len(subdomains),
        "total_parameters": len(parameters),
    }
