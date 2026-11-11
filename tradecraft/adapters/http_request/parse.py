from __future__ import annotations

from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from tradecraft.adapters.http_request.execute import METRICS_DELIMITER

DEFAULT_MAX_BODY_CHARS = 2000


def host_port_from_url(url: str) -> Tuple[str, int]:
    cleaned = (url or "").strip()
    if not cleaned:
        return ("", 80)
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urlparse(cleaned)
    host = parsed.hostname or ""
    if parsed.port:
        return (host, parsed.port)
    return (host, 443 if parsed.scheme == "https" else 80)


def evidence_target_from_url(url: str) -> str:
    """EvidenceStore target for a request: bare host when the URL has no
    distinguishing path (the common single-fetch-per-host case -- keeps
    read_evidence(target=<host>, ...) working exactly as it always has),
    host+path when it does. Without this, two different URLs fetched
    against the same host (e.g. two distinct JS chunks, or an API's root
    vs. a specific sub-path) collapse onto the same bare-host evidence
    slot and silently overwrite one another -- a real run needed an
    avoidable re-fetch to recover a chunk evicted this way. A bare-host
    read_evidence call still resolves correctly afterwards via
    EvidenceStore.read()'s sibling-path fallback when exactly one
    path-qualified entry exists under that host."""
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urlparse(cleaned)
    host = parsed.hostname or ""
    path = parsed.path or ""
    if path and path != "/":
        return f"{host}{path}"
    return host


def parse_curl_headers(raw_headers: str) -> Dict[str, str]:
    if not raw_headers:
        return {}
    # If redirects were followed, raw_headers contains multiple HTTP blocks separated by double newlines
    blocks = [b.strip() for b in raw_headers.replace("\r\n", "\n").split("\n\n") if b.strip()]
    if not blocks:
        return {}
    # Take the last header block (the final response after redirects)
    last_block = blocks[-1]
    headers: Dict[str, str] = {}
    lines = last_block.split("\n")
    for line in lines[1:]:  # skip HTTP status line (e.g. HTTP/2 200)
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        headers[key.strip()] = val.strip()
    return headers


def parse_http_response(
    raw_result: Dict[str, Any],
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
    body_offset: int = 0,
) -> Dict[str, Any]:
    url = raw_result.get("url", "")
    method = raw_result.get("method", "GET")

    if "error" in raw_result:
        return {
            "url": url,
            "method": method,
            "status_code": 0,
            "error": raw_result["error"],
        }

    stdout = raw_result.get("stdout", "")
    status_code = 0
    duration_seconds = 0.0
    effective_url = url

    if METRICS_DELIMITER in stdout:
        _, _, metrics_part = stdout.partition(METRICS_DELIMITER)
        metric_lines = [l.strip() for l in metrics_part.strip().splitlines() if l.strip()]
        if len(metric_lines) >= 1 and metric_lines[0].isdigit():
            status_code = int(metric_lines[0])
        if len(metric_lines) >= 2:
            try:
                duration_seconds = round(float(metric_lines[1]), 3)
            except ValueError:
                duration_seconds = 0.0
        if len(metric_lines) >= 3:
            effective_url = metric_lines[2]

    returncode = raw_result.get("returncode", 0)
    stderr = (raw_result.get("stderr") or "").strip()

    if returncode != 0 and status_code == 0:
        return {
            "url": url,
            "method": method,
            "status_code": 0,
            "error": stderr or f"curl exited with code {returncode}",
        }

    raw_headers = raw_result.get("raw_headers", "")
    headers = parse_curl_headers(raw_headers)

    content_type = ""
    server = ""
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower == "content-type":
            content_type = v
        elif k_lower == "server":
            server = v

    raw_body = raw_result.get("raw_body", "")
    total_len = len(raw_body)
    start = min(max(0, body_offset), total_len)
    end = min(start + max_body_chars, total_len)
    body = raw_body[start:end]
    next_body_offset = end if end < total_len else None
    body_truncated = next_body_offset is not None
    if body_truncated:
        evidence_target = evidence_target_from_url(url)
        body += (
            f"\n... [showing chars {start}-{end} of {total_len}; "
            f"pass body_offset={end} for the next chunk, or "
            f"read_evidence(target='{evidence_target}', tool_id='http_request') for the full body]"
        )

    parsed: Dict[str, Any] = {
        "url": url,
        "effective_url": effective_url,
        "method": method,
        "status_code": status_code,
        "duration_seconds": duration_seconds,
        "content_type": content_type,
        "server": server,
        "headers": headers,
        "body_length": total_len,
        "body_offset": start,
        "body_truncated": body_truncated,
        "next_body_offset": next_body_offset,
        "body": body,
    }

    if stderr and returncode != 0:
        parsed["warning"] = stderr

    return parsed
