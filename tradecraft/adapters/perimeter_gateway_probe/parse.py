"""
Pure parsing for perimeter_gateway_probe.
Extracts confirmed vulnerabilities, appliance fingerprints, and diagnostic
telemetry from raw probe results. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.perimeter_gateway_probe.execute import ApplianceProbeResult, RawPerimeterResult


def parse_perimeter_result(raw: RawPerimeterResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    vulnerable_findings: List[Dict[str, Any]] = []
    detected_appliances: List[Dict[str, Any]] = []
    unverified_exposures: List[Dict[str, Any]] = []
    all_probes: List[Dict[str, Any]] = []

    for r in raw.results:
        probe_summary = {
            "appliance": r.appliance,
            "cve": r.cve,
            "url": r.target_url,
            "fingerprinted": r.fingerprinted,
            "vulnerable": r.vulnerable,
            "requires_manual_verification": r.requires_manual_verification,
            "status_code": r.status_code,
            "evidence": r.evidence_snippet[:300] if r.evidence_snippet else "",
            "error": r.error,
        }
        all_probes.append(probe_summary)

        if r.fingerprinted and r.requires_manual_verification:
            # Exposure confirmed, but this prober never tests an exploit
            # path (see e.g. probe_fortinet) -- a distinct bucket from
            # "tested and came back safe," which this isn't.
            unverified_exposures.append({
                "appliance": r.appliance,
                "cve": r.cve,
                "url": r.target_url,
                "details": r.evidence_snippet[:300],
            })
        elif r.fingerprinted:
            detected_appliances.append({
                "appliance": r.appliance,
                "url": r.target_url,
                "status_code": r.status_code,
                "details": r.evidence_snippet[:300],
            })

        if r.vulnerable:
            vulnerable_findings.append({
                "appliance": r.appliance,
                "cve": r.cve,
                "url": r.target_url,
                "evidence": r.evidence_snippet[:300],
            })

    if vulnerable_findings:
        cve_list = ", ".join(f["cve"] for f in vulnerable_findings)
        summary = (
            f"CRITICAL VULNERABILITY: Confirmed perimeter gateway vulnerability on {raw.base_url} "
            f"({cve_list})."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": True,
            "status": "vulnerable",
            "summary": summary,
            "vulnerable_appliances": vulnerable_findings,
            "detected_appliances": detected_appliances,
            "unverified_exposures": unverified_exposures,
            "probes_evaluated": all_probes,
            "recommendation": (
                "Immediately isolate affected perimeter gateways and apply vendor emergency patches "
                "(Check Point sk182336, Palo Alto PAN-OS hotfixes, Ivanti mitigation XML/patch, Citrix advisory, "
                "Fortinet FG-IR-22-398/FG-IR-23-097/FG-IR-24-015)."
            ),
        }

    if unverified_exposures:
        # Confirmed exposure of an appliance whose CVEs this tool never
        # actively tests (see probe_fortinet) -- distinct from "safe": no
        # exploit path was tested, so "patch appears present" would be the
        # wrong conclusion here.
        names = ", ".join(a["appliance"] for a in unverified_exposures)
        summary = (
            f"EXPOSURE CONFIRMED, NOT TESTED: {names} detected on {raw.base_url}. "
            f"This appliance's CVEs were not actively tested (unsafe to trigger blindly) "
            f"-- verify its firmware build against the vendor's advisory before concluding "
            f"it is patched."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": False,
            "status": "exposed_unverified",
            "summary": summary,
            "unverified_exposures": unverified_exposures,
            "detected_appliances": detected_appliances,
            "probes_evaluated": all_probes,
        }

    if detected_appliances:
        names = ", ".join(a["appliance"] for a in detected_appliances)
        summary = (
            f"SAFE: Detected perimeter appliance(s) ({names}) on {raw.base_url}, but tested CVE exploit "
            f"paths returned no vulnerable behavior (patch appears present)."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": False,
            "status": "safe",
            "summary": summary,
            "detected_appliances": detected_appliances,
            "probes_evaluated": all_probes,
        }

    summary = (
        f"NOT_APPLICABLE: No known perimeter gateway signatures (Check Point, Palo Alto, Ivanti, Citrix, "
        f"Fortinet) responded on {raw.base_url} across {len(raw.results)} probe(s)."
    )
    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "vulnerable": False,
        "status": "not_applicable",
        "summary": summary,
        "probes_evaluated": all_probes,
    }
