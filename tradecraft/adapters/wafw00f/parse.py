"""
Pure parsing: wafw00f's -f json output -> a sorted list of detected WAF
names (empty if none found). No subprocess, no I/O.
"""
from __future__ import annotations

import json
from typing import List, Optional, Tuple


def parse_wafs(json_output: str) -> List[str]:
    json_output = json_output.strip()
    if not json_output:
        return []
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    wafs = {
        entry.get("waf") for entry in data
        if isinstance(entry, dict) and entry.get("waf") and entry.get("waf") != "None"
    }
    return sorted(wafs)


def host_port_from_target(target: str) -> Tuple[str, Optional[int]]:
    """'host' -> (host, None); 'host:port' -> (host, port)."""
    host_part = target.split("://", 1)[-1].split("/", 1)[0]
    if ":" in host_part:
        host, port_str = host_part.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
    return host_part, None
