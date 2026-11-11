"""
Pure parsing functions for arjun parameter discovery output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Set, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_arjun_output(json_output: str, stdout: str = "") -> Dict[str, Any]:
    """Parses arjun output from either its JSON file output or stdout summary."""
    parameters: Set[str] = set()

    # 1. Try parsing JSON output file content
    if json_output and json_output.strip():
        try:
            data = json.loads(json_output)
            if isinstance(data, dict):
                for _, val in data.items():
                    if isinstance(val, dict):
                        # Modern Arjun format: {"url": {"method": "GET", "params": ["p1", "p2"]}}
                        plist = val.get("params") or val.get("parameters")
                        if isinstance(plist, list):
                            for p in plist:
                                if isinstance(p, str) and p.strip():
                                    parameters.add(p.strip())
                    elif isinstance(val, list):
                        # Flat mapping format: {"url": ["p1", "p2"]}
                        for p in val:
                            if isinstance(p, str) and p.strip():
                                parameters.add(p.strip())
            elif isinstance(data, list):
                # Array of parameter names: ["p1", "p2"]
                for p in data:
                    if isinstance(p, str) and p.strip():
                        parameters.add(p.strip())
        except json.JSONDecodeError:
            pass

    # 2. Fallback to parsing stdout if JSON had no findings
    if not parameters and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            # E.g. "[+] Parameters found: _action, token"
            if "parameters found:" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    found_str = parts[1].strip()
                    tokens = [t.strip() for t in found_str.split(",") if t.strip()]
                    parameters.update(tokens)
            # E.g. "[✓] parameter detected: _action, based on: param value reflection"
            match = re.search(r"parameter detected:\s*([a-zA-Z0-9_\-]+)", line, re.IGNORECASE)
            if match:
                parameters.add(match.group(1).strip())
            # E.g. legacy: "[+] query : id" or "[+] body : token"
            match_legacy = re.search(r"\[\+\]\s*(?:query|body|json)\s*:\s*([a-zA-Z0-9_\-]+)", line, re.IGNORECASE)
            if match_legacy:
                parameters.add(match_legacy.group(1).strip())

    sorted_params = sorted(parameters)
    return {
        "parameters": sorted_params,
        "total_parameters": len(sorted_params),
    }
