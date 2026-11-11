"""
Pure parsing: whatweb's --log-json=- stdout (a JSON array with one
record) -> a plain dict of {url, host, port, tech}. No subprocess, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# Plugins that describe HTTP response plumbing (headers, cookies, IP/
# country geolocation) rather than actual technology -- filtered out so
# `tech` stays a signal list, not a restating of raw headers.
_EXCLUDED_PLUGINS = {
    "uncommonheaders", "country", "ip", "cookies", "title", "script",
    "email", "meta-author", "html5", "httponly", "strict-transport-security",
    "x-frame-options", "x-xss-protection", "x-ua-compatible", "x-powered-by",
    "content-security-policy", "redirectlocation", "via-proxy",
    "access-control-allow-origin", "frame", "meta-refresh-redirect",
}


def _host_port_from_url(url: str) -> tuple[Optional[str], Optional[int]]:
    host_part = url.split("://", 1)[-1].split("/", 1)[0]
    if ":" in host_part:
        host, port_str = host_part.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
        return host, None
    return host_part, (443 if url.startswith("https://") else 80)


def parse_fingerprint(stdout: str) -> Optional[Dict[str, Any]]:
    stdout = stdout.strip()
    if not stdout:
        return None
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    rec = data[0] if isinstance(data, list) and data else data
    if not isinstance(rec, dict):
        return None

    plugins = rec.get("plugins", {})
    tech: List[str] = sorted(name for name in plugins if name.lower() not in _EXCLUDED_PLUGINS)

    url = rec.get("target")
    host, port = _host_port_from_url(url) if url else (None, None)
    return {"url": url, "host": host, "port": port, "tech": tech}
