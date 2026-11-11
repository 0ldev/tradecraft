"""
Pure parsing functions for cloud_enum output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0].split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 443)
    return host, port


def parse_cloudenum_output(
    json_content: str = "",
    stdout: str = "",
) -> Dict[str, Any]:
    """
    Parses cloud_enum JSON findings from log file or stdout.
    The log format from cloud_enum is newline-delimited JSON objects,
    sometimes preceded by a header banner line '#### CLOUD_ENUM ... ####'.
    """
    raw_lines: List[str] = []
    if json_content and json_content.strip():
        raw_lines.extend(json_content.splitlines())
    elif stdout and stdout.strip():
        raw_lines.extend(stdout.splitlines())

    resources: List[Dict[str, Any]] = []
    by_platform: Dict[str, int] = {}
    public_count = 0
    protected_count = 0
    disabled_count = 0

    for line in raw_lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(item, dict):
            continue

        platform = str(item.get("platform", "")).strip().lower()
        resource = str(item.get("target", "")).strip()
        msg = str(item.get("msg", "")).strip()
        access = str(item.get("access", "")).strip().lower()

        if not resource and not msg:
            continue

        is_public = (access == "public" or "open" in msg.lower())

        if is_public:
            public_count += 1
        elif access == "protected" or "protected" in msg.lower():
            protected_count += 1
        elif access == "disabled" or "disabled" in msg.lower():
            disabled_count += 1

        if platform:
            by_platform[platform] = by_platform.get(platform, 0) + 1

        resources.append({
            "platform": platform,
            "resource": resource,
            "message": msg,
            "access": access,
            "is_public": is_public,
        })

    return {
        "resources": resources,
        "total_resources": len(resources),
        "public_count": public_count,
        "protected_count": protected_count,
        "disabled_count": disabled_count,
        "by_platform": by_platform,
    }
