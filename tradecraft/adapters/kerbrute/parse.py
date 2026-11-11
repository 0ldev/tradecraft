"""
Pure parsing and username extraction for kerbrute.
No subprocess or network I/O here.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_VALID_USER_REGEX = re.compile(r"\[\+\]\s+VALID USERNAME:\s+([^\s]+)", re.IGNORECASE)

DEFAULT_USERNAMES_WORDLIST = "kerbrute-usernames.txt"


@dataclass
class RawKerbruteResult:
    target: str = ""
    domain: str = ""
    usernames: List[str] = field(default_factory=list)
    stdout: str = ""
    error: Optional[str] = None


def normalize_target_host(target: str) -> str:
    """Normalize target string to hostname/IP without protocol or port."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        target = parsed.hostname or target
    elif ":" in target:
        target = target.split(":", 1)[0].strip()
    return target.strip("/")


def parse_host_port(target: str, default_port: int = 88) -> Tuple[str, int]:
    """Extract host and port from target string."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        host = parsed.hostname or target
        port = parsed.port or default_port
        return host, port
    if ":" in target:
        parts = target.split(":", 1)
        try:
            return parts[0].strip(), int(parts[1].strip())
        except ValueError:
            return parts[0].strip(), default_port
    return target, default_port


def parse_kerbrute_output(stdout: str) -> List[str]:
    """Extracts valid username identifiers from kerbrute stdout."""
    if not stdout:
        return []

    found = []
    seen = set()
    for line in stdout.splitlines():
        match = _VALID_USER_REGEX.search(line)
        if match:
            username = match.group(1).strip()
            if username and username.lower() not in seen:
                seen.add(username.lower())
                found.append(username)

    return found


def parse_kerbrute_result(raw: RawKerbruteResult) -> Dict[str, Any]:
    """Transforms raw probe result into structured output."""
    return {
        "target": raw.target,
        "domain": raw.domain,
        "total_users_found": len(raw.usernames),
        "usernames": raw.usernames,
        "error": raw.error,
    }
