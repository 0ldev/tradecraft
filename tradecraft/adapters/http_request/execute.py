from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 10
METRICS_DELIMITER = "---CURL_METRICS---"

# http_request is the always-available, non-destructive tool: it may only
# issue methods that don't create persistent state the model would need to
# track or undo (GET/HEAD/OPTIONS are safe by HTTP convention; POST is kept
# here too because it's genuinely dual-use -- login/search/form-probing
# POSTs are routine non-destructive testing).
# PUT/DELETE/PATCH are real writes/deletes that don't undo themselves --
# see tradecraft/adapters/http_write_request/, the destructive: true sibling
# gated behind --allow-destructive.
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}


def normalize_target_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        return f"https://{cleaned}"
    return cleaned


def normalize_urls(url: str) -> List[str]:
    """Comma-split and trim, preserving order and removing duplicates --
    same convention as httpx's normalize_targets, dnsx's, and
    shodan_internetdb's. Lets the tool layer confirm the same request
    shape across several known URLs in one call instead of one call per
    URL."""
    seen = set()
    urls: List[str] = []
    for u in (url or "").split(","):
        s = u.strip()
        if s and s not in seen:
            seen.add(s)
            urls.append(s)
    return urls


def build_argv(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    follow_redirects: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    header_file: Optional[str] = None,
    body_file: Optional[str] = None,
) -> List[str]:
    target_url = normalize_target_url(url)
    http_method = (method or "GET").strip().upper()

    argv = ["curl", "-s", "-S", "-k", "--max-time", str(max(1, timeout))]

    if http_method:
        argv.extend(["-X", http_method])

    if follow_redirects:
        argv.append("-L")

    if headers:
        for line in headers.splitlines():
            line = line.strip()
            if line:
                argv.extend(["-H", line])

    if data is not None:
        argv.extend(["-d", data])

    if header_file:
        argv.extend(["-D", header_file])

    if body_file:
        argv.extend(["-o", body_file])

    argv.extend(["-w", f"\n{METRICS_DELIMITER}\n%{{http_code}}\n%{{time_total}}\n%{{url_effective}}\n"])
    argv.append(target_url)
    return argv


def execute(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    follow_redirects: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    binary: str = "curl",
) -> Dict[str, Any]:
    http_method = (method or "GET").strip().upper()
    if http_method not in ALLOWED_METHODS:
        return {
            "url": normalize_target_url(url),
            "method": http_method,
            "error": (
                f"method '{http_method}' is a state-mutating write/delete and not "
                "permitted via http_request (allowed: GET, HEAD, OPTIONS, POST). "
                "Use the destructive http_write_request tool (requires "
                "--allow-destructive) for PUT, DELETE, or PATCH."
            ),
        }
    return execute_unchecked(
        url=url, method=http_method, headers=headers, data=data,
        follow_redirects=follow_redirects, timeout=timeout, binary=binary,
    )


def execute_unchecked(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    follow_redirects: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    binary: str = "curl",
) -> Dict[str, Any]:
    """Runs the actual curl subprocess for any method, with no method
    allowlist of its own -- callers must validate `method` first. Shared
    by this module's own `execute()` (GET/HEAD/OPTIONS/POST) and
    tradecraft/adapters/http_write_request/execute.py's `execute()`
    (PUT/DELETE/PATCH), which each apply their own disjoint allowlist
    before calling this, so the subprocess/argv-construction logic below
    isn't duplicated between the safe and destructive tool."""
    target_url = normalize_target_url(url)
    if not target_url:
        return {"error": "empty url provided"}

    if not shutil.which(binary):
        return {
            "error": f"required binary '{binary}' not found on PATH; "
                     f"install curl in the runtime environment"
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        header_path = str(Path(tmpdir) / "headers.txt")
        body_path = str(Path(tmpdir) / "body.txt")

        argv = build_argv(
            url=target_url,
            method=method,
            headers=headers,
            data=data,
            follow_redirects=follow_redirects,
            timeout=timeout,
            header_file=header_path,
            body_file=body_path,
        )

        try:
            # Allow a margin over curl's own internal --max-time
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
        except subprocess.TimeoutExpired:
            return {
                "url": target_url,
                "method": method,
                "error": f"request timed out after {timeout}s",
            }
        except Exception as exc:
            return {
                "url": target_url,
                "method": method,
                "error": f"failed to execute curl: {exc}",
            }

        raw_headers = ""
        if os.path.exists(header_path):
            try:
                raw_headers = Path(header_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw_headers = ""

        raw_body = ""
        if os.path.exists(body_path):
            try:
                raw_body = Path(body_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw_body = ""

        return {
            "url": target_url,
            "method": (method or "GET").strip().upper(),
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
            "raw_headers": raw_headers,
            "raw_body": raw_body,
        }
