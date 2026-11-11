"""
Pure parsing functions for katana crawler output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Set, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_katana_output(stdout: str) -> Dict[str, Any]:
    """Parses newline-delimited JSON output from katana crawler into structured
    endpoint and parameter dictionaries."""
    seen_endpoints: Set[Tuple[str, str]] = set()
    endpoints: List[Dict[str, Any]] = []
    all_parameters: Set[str] = set()

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

        req = data.get("request", {})
        if not isinstance(req, dict):
            continue

        endpoint = req.get("endpoint")
        if not endpoint or not isinstance(endpoint, str):
            continue

        method = req.get("method", "GET").upper()
        dedup_key = (method, endpoint)
        if dedup_key in seen_endpoints:
            continue
        seen_endpoints.add(dedup_key)

        tag = req.get("tag")
        resp = data.get("response")
        status_code = resp.get("status_code") if isinstance(resp, dict) else None

        parsed = urllib.parse.urlsplit(endpoint)
        path = parsed.path or "/"

        params_list: List[str] = []
        if parsed.query:
            try:
                # keep_blank_values=True ensures parameter names with empty values
                # (e.g. ?q= or ?search=) are preserved
                query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params_list = sorted(query_params.keys())
                all_parameters.update(params_list)
            except Exception:
                pass

        record: Dict[str, Any] = {
            "endpoint": endpoint,
            "path": path,
            "method": method,
        }
        if status_code is not None:
            record["status_code"] = int(status_code)
        if tag and isinstance(tag, str):
            record["tag"] = tag
        if params_list:
            record["parameters"] = params_list

        endpoints.append(record)

    return {
        "endpoints": endpoints,
        "parameters": sorted(all_parameters),
        "total_endpoints": len(endpoints),
        "total_parameters": len(all_parameters),
    }
