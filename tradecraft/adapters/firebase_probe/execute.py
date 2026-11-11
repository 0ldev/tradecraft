"""
Raw execution for firebase_probe: one unauthenticated GET per datastore per
candidate project ID. Read-only -- no write is ever attempted. No parsing
here -- that's parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

RTDB_SNIPPET_LIMIT = 500


@dataclass
class FirebaseCheck:
    project_id: str
    rtdb_status: Optional[int] = None
    rtdb_readable: bool = False
    rtdb_body_snippet: str = ""
    firestore_status: Optional[int] = None
    firestore_readable: bool = False
    error: Optional[str] = None


@dataclass
class RawFirebaseResult:
    checks: List[FirebaseCheck] = field(default_factory=list)
    error: Optional[str] = None


def _get(url: str, timeout: int):
    return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, verify=False)


def _check_rtdb(check: FirebaseCheck, timeout: int) -> None:
    url = f"https://{check.project_id}-default-rtdb.firebaseio.com/.json?print=pretty&limitToFirst=5"
    try:
        resp = _get(url, timeout)
    except requests.RequestException as exc:
        # DNS/connection failure: this project ID has no RTDB instance reachable.
        check.error = f"RTDB: {exc}"
        return
    check.rtdb_status = resp.status_code
    if resp.status_code == 200 and resp.text.strip() != "null":
        check.rtdb_readable = True
        check.rtdb_body_snippet = resp.text[:RTDB_SNIPPET_LIMIT]


def _check_firestore(check: FirebaseCheck, timeout: int) -> None:
    url = f"https://firestore.googleapis.com/v1/projects/{check.project_id}/databases/(default)/documents"
    try:
        resp = _get(url, timeout)
    except requests.RequestException as exc:
        check.error = f"Firestore: {exc}"
        return
    check.firestore_status = resp.status_code
    if resp.status_code == 200:
        try:
            json.loads(resp.text)
        except ValueError:
            check.error = "Firestore: HTTP 200 with a non-JSON body"
            return
        check.firestore_readable = True


def execute(project_ids: str, timeout: int = 10) -> RawFirebaseResult:
    raw = RawFirebaseResult()
    if requests is None:
        raw.error = "requests library not available"
        return raw

    candidates = [p.strip() for p in (project_ids or "").split(",") if p.strip()]
    if not candidates:
        raw.error = "no project IDs given"
        return raw

    for project_id in candidates:
        check = FirebaseCheck(project_id=project_id)
        _check_rtdb(check, timeout)
        _check_firestore(check, timeout)
        raw.checks.append(check)
    return raw
