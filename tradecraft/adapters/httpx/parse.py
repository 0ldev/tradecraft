"""
Pure parsing: httpx's -json stdout (one JSON object per line if the host
answered, nothing at all if it didn't) -> a plain dict, or None if the
host isn't live. No subprocess, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _parse_line(data: dict) -> Dict[str, Any]:
    headers = {k.lower().replace("_", "-"): v for k, v in (data.get("header") or {}).items()}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    return {
        "host": data.get("host") or data.get("input"),
        "port": data.get("port"),
        "url": data.get("url"),
        "status_code": data.get("status_code"),
        "title": data.get("title"),
        "webserver": data.get("webserver"),
        "tech": data.get("tech", []),
        "missing_security_headers": missing,
    }


def parse_probe(stdout: str) -> Optional[Dict[str, Any]]:
    """Unchanged signature/behavior: first valid JSON line only, via _parse_line()."""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        return _parse_line(data)
    return None


def parse_probe_many(stdout: str) -> List[Dict[str, Any]]:
    """Every valid JSON line, each via _parse_line() -- bulk counterpart."""
    results: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append(_parse_line(data))
    return results


def parse_raw(stdout: str) -> Optional[Dict[str, Any]]:
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def parse_raw_many(stdout: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results
