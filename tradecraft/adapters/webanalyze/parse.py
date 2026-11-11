"""
Pure parsing functions for webanalyze output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_webanalyze_output(stdout: str) -> List[Dict[str, str]]:
    """Parse JSONL output from webanalyze into a list of technology dicts.
    Each item has {'name': str, 'version': str}.
    Deduplicates technologies by name, preserving non-empty versions."""
    if not stdout or not stdout.strip():
        return []

    tech_map: Dict[str, str] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue

        matches = data.get("matches")
        if not isinstance(matches, list):
            continue

        for match in matches:
            if not isinstance(match, dict):
                continue
            name = match.get("app_name")
            if not name:
                continue
            name_str = str(name).strip()
            version = match.get("version")
            ver_str = str(version).strip() if version else ""

            if name_str not in tech_map:
                tech_map[name_str] = ver_str
            elif not tech_map[name_str] and ver_str:
                tech_map[name_str] = ver_str

    return [{"name": name, "version": tech_map[name]} for name in sorted(tech_map.keys())]
