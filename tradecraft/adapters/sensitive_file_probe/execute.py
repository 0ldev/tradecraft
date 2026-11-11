"""
Execution logic for sensitive_file_probe: GETs a fixed, bounded list of
high-value sensitive file paths against a target, plus one definitely-
nonexistent baseline path first so parse.py can tell a real hit apart
from a soft-404 (a custom "not found" page served with status 200).
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 200_000

CANDIDATE_PATHS = (
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/terraform.tfstate",
    "/docker-compose.yml",
    "/.DS_Store",
    "/backup.sql",
    "/database.sql",
    "/.npmrc",
    "/.ssh/id_rsa",
    "/id_rsa",
    "/debug.log",
    "/wp-config.php.bak",
    "/config.json.bak",
    "/.htpasswd",
)


@dataclass
class RawFileFetch:
    path: str
    status_code: int = 0
    content_type: str = ""
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawSensitiveFileResult:
    target: str = ""
    baseline: Optional[RawFileFetch] = None
    candidates: List[RawFileFetch] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t.rstrip("/")


def _fetch(base_url: str, path: str, headers: Dict[str, str], timeout: int) -> RawFileFetch:
    url = base_url + path
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return RawFileFetch(
            path=path,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type", ""),
            body=resp.text[:MAX_BODY_BYTES] if resp.text else "",
        )
    except requests.RequestException as exc:
        return RawFileFetch(path=path, error=str(exc))
    except Exception as exc:
        return RawFileFetch(path=path, error=f"{type(exc).__name__}: {exc}")


def execute(target: str, timeout: int = DEFAULT_TIMEOUT) -> RawSensitiveFileResult:
    if requests is None:
        return RawSensitiveFileResult(target=target, error="requests library not available")

    base_url = normalize_target_url(target)
    if not base_url:
        return RawSensitiveFileResult(target=target, error="empty target URL")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}

    baseline_path = f"/tradecraft-nonexistent-{secrets.token_hex(6)}.probe"
    baseline = _fetch(base_url, baseline_path, headers, timeout)
    if baseline.error:
        return RawSensitiveFileResult(target=base_url, baseline=baseline, error=baseline.error)

    candidates = [_fetch(base_url, path, headers, timeout) for path in CANDIDATE_PATHS]

    return RawSensitiveFileResult(target=base_url, baseline=baseline, candidates=candidates)
