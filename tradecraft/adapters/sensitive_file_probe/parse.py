"""
Pure parsing for sensitive_file_probe: decides which candidate paths are
real sensitive-file hits rather than a soft-404 that happens to return
200. No I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.sensitive_file_probe.execute import RawFileFetch, RawSensitiveFileResult

MAX_SNIPPET_BYTES = 500

# Per-path content-shape heuristics: a regex the body must match to count
# as a real hit, beyond "status differs from the baseline". A path with
# no entry here is flagged on status/length difference from baseline alone.
_SHAPE_CHECKS: Dict[str, re.Pattern] = {
    "/.env": re.compile(r"^[A-Z0-9_]+\s*=", re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|\[remote\s"),
    "/.git/HEAD": re.compile(r"^ref:\s+refs/"),
    "/.aws/credentials": re.compile(r"\[default\]|aws_access_key_id", re.IGNORECASE),
    "/terraform.tfstate": re.compile(r'"version"\s*:\s*\d+'),
    "/docker-compose.yml": re.compile(r"^\s*(version|services)\s*:", re.MULTILINE),
    "/.npmrc": re.compile(r"registry\s*=|_authToken"),
    "/.ssh/id_rsa": re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"),
    "/id_rsa": re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"),
    "/.htpasswd": re.compile(r"^[^:\s]+:\$?\w+\$", re.MULTILINE),
}


def _looks_like_real_hit(candidate: RawFileFetch, baseline: RawFileFetch) -> bool:
    if candidate.status_code != 200:
        return False
    body = candidate.body or ""
    if not body.strip():
        return False
    # Identical to the baseline 404 body -> a soft-404 template, not a hit.
    if baseline.body and body.strip() == baseline.body.strip():
        return False

    shape = _SHAPE_CHECKS.get(candidate.path)
    if shape is not None:
        return bool(shape.search(body))

    # No specific shape check for this path (e.g. .DS_Store, backup.sql,
    # debug.log): fall back to "differs from the html-shaped baseline and
    # isn't itself HTML", since these targets are never a normal page.
    content_type = (candidate.content_type or "").lower()
    if "text/html" in content_type:
        return False
    return True


def parse(raw: RawSensitiveFileResult) -> Dict[str, Any]:
    if raw.error:
        return {"target": raw.target, "error": raw.error}

    baseline = raw.baseline
    if baseline is None:
        return {"target": raw.target, "error": "No baseline response recorded"}

    hits: List[Dict[str, Any]] = []
    checked: List[Dict[str, Any]] = []

    for cand in raw.candidates:
        if cand.error:
            checked.append({"path": cand.path, "status_code": 0, "error": cand.error})
            continue

        is_hit = _looks_like_real_hit(cand, baseline)
        entry: Dict[str, Any] = {
            "path": cand.path,
            "status_code": cand.status_code,
            "content_type": cand.content_type,
            "hit": is_hit,
        }
        if is_hit:
            entry["body_snippet"] = cand.body[:MAX_SNIPPET_BYTES]
            hits.append(entry)
        checked.append(entry)

    return {
        "target": raw.target,
        "baseline_status_code": baseline.status_code,
        "paths_checked": len(raw.candidates),
        "hits_found": len(hits),
        "hits": hits,
        "checked": checked,
    }
