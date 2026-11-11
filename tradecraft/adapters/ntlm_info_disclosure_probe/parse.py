"""
Pure parsing for ntlm_info_disclosure_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.ntlm_info_disclosure_probe.execute import RawNtlmResult


def parse(raw: RawNtlmResult) -> Dict[str, Any]:
    domain = raw.nb_domain_name or raw.dns_domain_name or raw.target_name
    computer = raw.nb_computer_name or raw.dns_computer_name
    disclosed = bool(domain or computer or raw.dns_tree_name)

    if raw.error and not raw.challenge_received:
        return {
            "target": raw.target,
            "status_code": raw.status_code,
            "ntlm_supported": raw.ntlm_supported,
            "disclosed": False,
            "error": raw.error,
        }

    if not disclosed:
        summary = "NTLM challenge received, but it did not disclose a domain or hostname."
    else:
        parts = []
        if domain:
            parts.append(f"domain '{domain}'")
        if computer:
            parts.append(f"hostname '{computer}'")
        if raw.dns_tree_name and raw.dns_tree_name != domain:
            parts.append(f"tree '{raw.dns_tree_name}'")
        summary = "NTLM Type-2 challenge disclosed " + ", ".join(parts) + "."

    return {
        "target": raw.target,
        "status_code": raw.status_code,
        "auth_scheme": raw.auth_scheme,
        "ntlm_supported": raw.ntlm_supported,
        "challenge_received": raw.challenge_received,
        "disclosed": disclosed,
        "domain": domain,
        "computer_name": computer,
        "dns_domain_name": raw.dns_domain_name,
        "dns_computer_name": raw.dns_computer_name,
        "dns_tree_name": raw.dns_tree_name,
        "target_name": raw.target_name,
        "server_challenge": raw.server_challenge,
        "negotiate_flags": raw.negotiate_flags,
        "summary": summary,
        "error": raw.error,
    }
