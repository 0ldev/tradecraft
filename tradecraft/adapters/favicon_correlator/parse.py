"""
Pure parsing and hash calculation functions for favicon_correlator. No I/O here.
"""
from __future__ import annotations

import base64
from typing import Any, Dict, List

import mmh3


def compute_shodan_favicon_hash(favicon_bytes: bytes) -> int:
    """Shodan's favicon hash: MurmurHash3 of RFC 2045 base64-encoded bytes
    (with newlines inserted every 76 characters via base64.encodebytes)."""
    b64 = base64.encodebytes(favicon_bytes)
    return mmh3.hash(b64)


def parse_shodan_matches(shodan_data: Dict[str, Any]) -> List[str]:
    """Extract unique sorted IP strings from Shodan search matches."""
    if not isinstance(shodan_data, dict):
        return []
    matches = shodan_data.get("matches", [])
    if not isinstance(matches, list):
        return []
    ips = {
        m.get("ip_str")
        for m in matches
        if isinstance(m, dict) and m.get("ip_str")
    }
    return sorted(str(ip) for ip in ips)


def normalize_target_url(target: str) -> str:
    """Normalize target to full URL defaulting to https://."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"
