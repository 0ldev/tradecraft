"""
Pure parsing for magento_cosmicsting_probe (CVE-2024-34102).
Extracts vulnerability status, patched status, and diagnostic evidence
from the raw probe results. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.magento_cosmicsting_probe.execute import EndpointProbeResult, RawCosmicStingResult


def parse_cosmicsting_result(raw: RawCosmicStingResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    vulnerable_hits: List[Dict[str, Any]] = []
    patched_hits: List[Dict[str, Any]] = []
    responding_probes: List[Dict[str, Any]] = []

    for probe in raw.probes:
        entry = {
            "url": probe.url,
            "status_code": probe.status_code,
            "snippet": probe.body_snippet[:300] if probe.body_snippet else "",
            "error": probe.error,
        }
        responding_probes.append(entry)

        if probe.is_vulnerable_indicator:
            vulnerable_hits.append(entry)
        elif probe.is_patched_indicator:
            patched_hits.append(entry)

    if vulnerable_hits:
        status = "vulnerable"
        summary = (
            f"VULNERABLE: Target exhibits XML entity loading / parser error indicators "
            f"consistent with Adobe Commerce / Magento CosmicSting (CVE-2024-34102) on {vulnerable_hits[0]['url']}."
        )
        return {
            "target": raw.target,
            "vulnerable": True,
            "patched": False,
            "status": status,
            "summary": summary,
            "cart_id": raw.cart_id_used,
            "guest_cart_created": raw.guest_cart_created,
            "callback_url": raw.callback_url,
            "matched_endpoint": vulnerable_hits[0]["url"],
            "evidence_snippet": vulnerable_hits[0]["snippet"],
            "probed_endpoints": responding_probes,
            "recommendation": (
                "Apply Adobe Security Bulletin APSB24-40 immediately or update Magento to version "
                "2.4.7-p1, 2.4.6-p6, 2.4.5-p8, or 2.4.4-p9. Restrict access to /rest/*/guest-carts endpoints."
            ),
        }

    if patched_hits:
        status = "patched"
        summary = (
            f"PATCHED: Target rejected totalsCollector serialization on {patched_hits[0]['url']} "
            f"(APSB24-40 patch appears present)."
        )
        return {
            "target": raw.target,
            "vulnerable": False,
            "patched": True,
            "status": status,
            "summary": summary,
            "cart_id": raw.cart_id_used,
            "guest_cart_created": raw.guest_cart_created,
            "callback_url": raw.callback_url,
            "probed_endpoints": responding_probes,
        }

    # If all endpoints returned 404 or errors
    all_404 = all(p.status_code == 404 for p in raw.probes if p.status_code is not None)
    if all_404 and raw.probes:
        summary = (
            "NOT_APPLICABLE: Magento REST guest-carts endpoints returned 404 Not Found. "
            "The Magento REST API is either disabled, moved, or the target does not run Magento."
        )
        return {
            "target": raw.target,
            "vulnerable": False,
            "patched": False,
            "status": "not_applicable",
            "summary": summary,
            "cart_id": raw.cart_id_used,
            "guest_cart_created": raw.guest_cart_created,
            "probed_endpoints": responding_probes,
        }

    summary = (
        f"INCONCLUSIVE: No XML parser errors or patch rejection signatures observed across "
        f"{len(raw.probes)} probed endpoint(s)."
    )
    return {
        "target": raw.target,
        "vulnerable": False,
        "patched": False,
        "status": "inconclusive",
        "summary": summary,
        "cart_id": raw.cart_id_used,
        "guest_cart_created": raw.guest_cart_created,
        "probed_endpoints": responding_probes,
    }
