"""
Pure parsing functions for cloudfail output.
No subprocess or I/O logic here.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


def parse_cloudfail_output(stdout: str, target: str = "") -> Dict[str, Any]:
    """Parses cloudfail stdout into structured findings."""
    cleaned = stdout.strip() if stdout else ""
    if not cleaned:
        return {
            "target": target,
            "server_ip": "",
            "is_cloudflare": False,
            "origin_unmasked": False,
            "unmasked_origin_ips": [],
            "unmasked_subdomains": [],
            "cloudflare_subdomains": [],
            "dnsdumpster_hosts": [],
        }

    server_ip = ""
    ip_match = re.search(r"Server IP:\s*([0-9.]+)", cleaned)
    if ip_match:
        server_ip = ip_match.group(1).strip()

    is_cloudflare = False
    if "is part of the Cloudflare network!" in cleaned:
        is_cloudflare = True
    elif "is not part of the Cloudflare network" in cleaned:
        is_cloudflare = False

    # Extract Crimeflare unmasked IPs: [FOUND:IP] 1.2.3.4
    unmasked_origin_ips: List[str] = []
    seen_ips = set()
    for ip in re.findall(r"\[FOUND:IP\]\s*([0-9.]+)", cleaned):
        ip = ip.strip()
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unmasked_origin_ips.append(ip)

    # Extract DNSDumpster hosts: [FOUND:HOST] direct.example.com 1.2.3.4 AS1234 Provider Country
    # or [FOUND:DNS] / [FOUND:MX]
    dnsdumpster_hosts: List[Dict[str, str]] = []
    for host_match in re.finditer(r"\[FOUND:(?:HOST|DNS|MX)\]\s*([^\s]+)\s+([0-9.]+)(?:\s+([^\s]+))?(?:\s+(.+))?", cleaned):
        d = host_match.group(1).strip()
        ip = host_match.group(2).strip()
        asn = host_match.group(3).strip() if host_match.group(3) else ""
        rest = host_match.group(4).strip() if host_match.group(4) else ""
        dnsdumpster_hosts.append({
            "domain": d,
            "ip": ip,
            "as": asn,
            "provider": rest,
        })
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unmasked_origin_ips.append(ip)

    # Extract unmasked subdomains: [FOUND:SUBDOMAIN] direct.example.com IP: 1.2.3.4 HTTP: 200
    unmasked_subdomains: List[Dict[str, Any]] = []
    for sub_match in re.finditer(r"\[FOUND:SUBDOMAIN\]\s*([^\s]+)\s+IP:\s*([0-9.]+)\s+HTTP:\s*([0-9]+)", cleaned):
        sub = sub_match.group(1).strip()
        ip = sub_match.group(2).strip()
        code = int(sub_match.group(3).strip())
        unmasked_subdomains.append({
            "subdomain": sub,
            "ip": ip,
            "status_code": code,
        })
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unmasked_origin_ips.append(ip)

    # Extract Cloudflare-protected subdomains: [FOUND:SUBDOMAIN] portal.example.com ON CLOUDFLARE NETWORK!
    cf_subdomains: List[str] = []
    seen_cf_subs = set()
    for cf_sub in re.findall(r"\[FOUND:SUBDOMAIN\]\s*([^\s]+)\s+ON CLOUDFLARE NETWORK!", cleaned):
        cf_sub = cf_sub.strip()
        if cf_sub and cf_sub not in seen_cf_subs:
            seen_cf_subs.add(cf_sub)
            cf_subdomains.append(cf_sub)

    origin_unmasked = len(unmasked_origin_ips) > 0

    return {
        "target": target,
        "server_ip": server_ip,
        "is_cloudflare": is_cloudflare,
        "origin_unmasked": origin_unmasked,
        "unmasked_origin_ips": unmasked_origin_ips,
        "unmasked_subdomains": unmasked_subdomains,
        "cloudflare_subdomains": cf_subdomains,
        "dnsdumpster_hosts": dnsdumpster_hosts,
    }
