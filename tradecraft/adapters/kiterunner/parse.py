"""
Pure parsing functions for kiterunner (kr) JSON stream output.
No subprocess or I/O logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_kiterunner_output(stdout: str, target_url: str = "") -> Dict[str, Any]:
    """Parses JSON stream output from kiterunner into structured endpoints."""
    endpoints: List[Dict[str, Any]] = []
    seen = set()

    if not stdout or not stdout.strip():
        return {
            "target": target_url,
            "total_endpoints": 0,
            "endpoints": [],
        }

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue

        # Skip status messages
        if "message" in data and "path" not in data:
            continue

        path = data.get("path", "")
        if not path:
            continue

        method = data.get("method", "GET").upper()
        responses = data.get("responses") or []
        status_code = 0
        length = 0
        if responses and isinstance(responses, list):
            status_code = responses[0].get("sc", 0)
            length = responses[0].get("len", 0)

        # Ignore 404 Not Found or 0 (connection failure)
        if status_code in (0, 404):
            continue

        key = (method, path)
        if key in seen:
            continue
        seen.add(key)

        endpoints.append({
            "path": path,
            "method": method,
            "status_code": status_code,
            "length": length,
        })

    return {
        "target": target_url,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
    }
