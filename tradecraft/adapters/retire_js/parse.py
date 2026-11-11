"""
Pure parsing of retire.js JSON output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def parse_retire_output(stdout: str) -> Dict[str, Any]:
    """Parses retire.js JSON output, extracting vulnerable library components."""
    clean_stdout = stdout.strip()
    if not clean_stdout:
        return {
            "vulnerable": False,
            "vulnerable_components": [],
            "summary": [],
        }

    try:
        data = json.loads(clean_stdout)
    except json.JSONDecodeError:
        return {
            "vulnerable": False,
            "vulnerable_components": [],
            "summary": [],
        }

    file_entries = data.get("data", [])
    components: List[Dict[str, Any]] = []

    for entry in file_entries:
        file_path = entry.get("file", "")
        file_name = Path(file_path).name if file_path else ""
        for res in entry.get("results", []):
            comp_name = res.get("component", "")
            comp_version = res.get("version", "")
            vulns = res.get("vulnerabilities", [])
            if comp_name and comp_version:
                components.append({
                    "component": comp_name,
                    "version": comp_version,
                    "file": file_name,
                    "vulnerabilities_count": len(vulns),
                    "vulnerabilities": vulns,
                })

    summary = [f"{c['component']}@{c['version']}" for c in components]

    return {
        "vulnerable": bool(components),
        "vulnerable_components": components,
        "summary": summary,
    }
