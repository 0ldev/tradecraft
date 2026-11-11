"""
Pure parsing: dnsx's JSONL output -> structured list of DNS records.
No subprocess, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


def parse_dns_records(stdout: str) -> List[Dict[str, Any]]:
    """Parse dnsx JSON lines into structured DNS records."""
    if not stdout or not stdout.strip():
        return []

    records: List[Dict[str, Any]] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = data.get("host")
        if not host:
            continue

        status_code = data.get("status_code", "UNKNOWN")
        resolves = (status_code == "NOERROR") and any(
            data.get(k) for k in ("a", "aaaa", "cname", "mx", "ns", "txt", "soa")
        )

        rec: Dict[str, Any] = {
            "host": host,
            "status_code": status_code,
            "resolves": bool(resolves),
        }

        # Include standard record types when present and non-empty
        for field in ("a", "aaaa", "cname", "mx", "ns", "txt"):
            val = data.get(field)
            if val:
                rec[field] = val if isinstance(val, list) else [val]

        if data.get("soa"):
            rec["soa"] = data["soa"]

        cdn_val = data.get("cdn") or data.get("cdn_name")
        if cdn_val:
            rec["cdn"] = cdn_val

        asn_val = data.get("as_name") or data.get("asn") or data.get("as_number")
        if asn_val:
            rec["asn"] = asn_val

        records.append(rec)

    return records
