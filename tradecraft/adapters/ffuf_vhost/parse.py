"""
Parsing ffuf vhost fuzzing JSON output into structured vhost records.
Pure functions, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from tradecraft.adapters.ffuf.execute import CanarySignature


def parse_vhosts(
    json_output: str,
    baseline: Optional[CanarySignature],
    host: str,
) -> List[Dict[str, Any]]:
    """Parse ffuf results JSON, dropping entries identical to baseline noise."""
    if not json_output or not json_output.strip():
        return []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return []

    seen: Dict[str, Dict[str, Any]] = {}
    clean_host = host.strip().lower()

    for item in data.get("results", []):
        prefix = item.get("input", {}).get("FUZZ", "")
        if not prefix:
            continue
        prefix = str(prefix).strip().lower()
        if not prefix:
            continue

        status = item.get("status", 0)
        length = item.get("length")

        if baseline is not None and status == baseline.status_code and length == baseline.length:
            continue

        vhost_name = f"{prefix}.{clean_host}"
        if vhost_name not in seen:
            seen[vhost_name] = {
                "vhost": vhost_name,
                "status_code": status,
            }

    return sorted(seen.values(), key=lambda x: x["vhost"])
