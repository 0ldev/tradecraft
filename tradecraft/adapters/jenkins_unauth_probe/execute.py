"""
Raw execution for jenkins_unauth_probe: a handful of anonymous GETs against
a candidate Jenkins base URL. Read-only -- never submits a Groovy script,
never triggers a build, never calls any endpoint with side effects. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"


@dataclass
class RawJenkinsProbeResult:
    target: str = ""
    base_url: str = ""
    is_jenkins: bool = False
    jenkins_version: Optional[str] = None
    root_status: Optional[int] = None
    whoami_status: Optional[int] = None
    whoami_body: Dict[str, Any] = field(default_factory=dict)
    script_console_status: Optional[int] = None
    script_console_reachable: bool = False
    manage_status: Optional[int] = None
    manage_reachable: bool = False
    api_json_status: Optional[int] = None
    api_json: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def normalize_base_url(target: str) -> str:
    cleaned = (target or "").strip().rstrip("/")
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def execute(target: str, timeout: int = 10) -> RawJenkinsProbeResult:
    base_url = normalize_base_url(target)
    result = RawJenkinsProbeResult(target=target, base_url=base_url)
    if not base_url:
        result.error = "empty target"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    headers = {"User-Agent": USER_AGENT}

    try:
        root_resp = requests.get(base_url, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        result.error = f"GET {base_url} failed: {exc}"
        return result

    result.root_status = root_resp.status_code
    # Jenkins sends its own "X-Jenkins" header on every response, authenticated
    # or not -- this is the standard, documented fingerprint, more reliable
    # than title/body matching.
    jenkins_header = root_resp.headers.get("X-Jenkins")
    if jenkins_header:
        result.is_jenkins = True
        result.jenkins_version = jenkins_header

    if not result.is_jenkins:
        result.error = "X-Jenkins header not present -- target does not appear to be Jenkins"
        return result

    try:
        whoami_resp = requests.get(
            f"{base_url}/whoAmI/api/json", headers=headers, timeout=timeout
        )
        result.whoami_status = whoami_resp.status_code
        if whoami_resp.status_code == 200:
            try:
                result.whoami_body = whoami_resp.json()
            except ValueError:
                pass
    except requests.RequestException:
        pass

    try:
        script_resp = requests.get(f"{base_url}/script", headers=headers, timeout=timeout, allow_redirects=False)
        result.script_console_status = script_resp.status_code
        # A 200 (the console form itself) means the console page rendered
        # without being bounced to a login page (e.g. a 302/403).
        result.script_console_reachable = script_resp.status_code == 200
    except requests.RequestException:
        pass

    try:
        manage_resp = requests.get(f"{base_url}/manage", headers=headers, timeout=timeout, allow_redirects=False)
        result.manage_status = manage_resp.status_code
        result.manage_reachable = manage_resp.status_code == 200
    except requests.RequestException:
        pass

    try:
        api_resp = requests.get(f"{base_url}/api/json", headers=headers, timeout=timeout)
        result.api_json_status = api_resp.status_code
        if api_resp.status_code == 200:
            try:
                result.api_json = api_resp.json()
            except ValueError:
                pass
    except requests.RequestException:
        pass

    return result
