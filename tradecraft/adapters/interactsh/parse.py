from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

# interactsh-client emits RFC3339/RFC3339Nano timestamps, e.g.
# "2026-11-03T10:35:19.254726586Z" -- up to 9 fractional digits, which
# Python's datetime (microsecond precision, 6 digits) cannot parse
# directly. This regex extracts and truncates the fraction instead of
# relying on datetime.fromisoformat to accept the raw string.
_TIMESTAMP_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<offset>Z|[+-]\d{2}:?\d{2})?$"
)


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parses an interactsh-style timestamp into a timezone-aware
    datetime. Returns None on anything unparseable -- never raises, so
    a malformed or missing timestamp degrades to "unknown", not a
    crash."""
    if not ts:
        return None
    m = _TIMESTAMP_RE.match(ts.strip())
    if not m:
        return None
    frac = (m.group("frac") or "0")[:6].ljust(6, "0")
    offset = m.group("offset") or "Z"
    if offset == "Z":
        offset = "+00:00"
    elif ":" not in offset:
        offset = f"{offset[:3]}:{offset[3:]}"
    try:
        return datetime.fromisoformat(f"{m.group('base')}.{frac}{offset}")
    except ValueError:
        return None


def is_after(timestamp: str, reference: str) -> Optional[bool]:
    """True if `timestamp` is at or after `reference`. None if either
    is unparseable -- callers must treat None as "unknown", never as
    False, since a parse failure is not evidence the interaction
    predates the reference."""
    t = _parse_timestamp(timestamp)
    r = _parse_timestamp(reference)
    if t is None or r is None:
        return None
    return t >= r


def parse_interaction_record(raw: Dict[str, Any], generated_at: str = "") -> Dict[str, Any]:
    protocol = raw.get("protocol", "unknown")
    remote_address = raw.get("remote-address") or raw.get("remote_address", "")
    timestamp = raw.get("timestamp", "")
    q_type = raw.get("q-type") or raw.get("q_type", "")
    raw_request = raw.get("raw-request") or raw.get("raw_request", "")

    request_summary = ""
    if protocol == "http":
        first_line = raw_request.splitlines()[0] if raw_request else ""
        request_summary = first_line.strip()
    elif protocol == "dns":
        request_summary = f"DNS {q_type} query" if q_type else "DNS query"
    elif protocol == "smtp":
        request_summary = "SMTP connection"
    else:
        request_summary = f"{protocol} interaction"

    record: Dict[str, Any] = {
        "protocol": protocol,
        "remote_address": remote_address,
        "timestamp": timestamp,
        "query_type": q_type,
        "request_summary": request_summary,
        "raw_request": raw_request,
    }
    if generated_at:
        # Deterministic timing correlation, computed here instead of
        # left to the model's own timestamp arithmetic -- None means
        # "unparseable, unknown," never "before."
        record["after_domain_generated"] = is_after(timestamp, generated_at)
    return record


def parse_interactions_jsonl(jsonl_text: str, generated_at: str = "") -> List[Dict[str, Any]]:
    records = []
    if not jsonl_text:
        return records

    for line in jsonl_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                records.append(parse_interaction_record(data, generated_at=generated_at))
        except json.JSONDecodeError:
            continue

    return records
