"""
Pure parsing: SPF, DMARC, DKIM, MTA-STS, and TLS-RPT record scoring.
No subprocess, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from tradecraft.adapters.email_auth_posture.execute import RawEmailAuthResult


def score_spf(spf_records: List[str]) -> Dict[str, Any]:
    """Score SPF policy strength based on the 'all' qualifier."""
    if not spf_records:
        return {"present": False, "strength": "missing"}

    record = spf_records[0].strip()
    match = re.search(r"(?:^|\s)([-~+?]?all)(?:\s|$)", record, re.IGNORECASE)

    if match:
        qualifier = match.group(1).lower()
        if qualifier == "-all":
            strength = "strict"
        elif qualifier == "~all":
            strength = "weak"
        else:
            # '+all', 'all', '?all'
            strength = "permissive"
    else:
        # No 'all' mechanism present defaults to permissive
        strength = "permissive"

    res: Dict[str, Any] = {
        "present": True,
        "strength": strength,
        "record": record,
    }
    if len(spf_records) > 1:
        res["note"] = "multiple SPF records found -- itself a misconfiguration (RFC 7208)"
    return res


def score_dmarc(dmarc_records: List[str]) -> Dict[str, Any]:
    """Score DMARC policy strength based on the 'p=' tag and extract 'pct=' if present."""
    matching = [r.strip() for r in dmarc_records if r.strip().lower().startswith("v=dmarc1")]
    if not matching:
        return {"present": False, "strength": "missing"}

    record = matching[0]

    p_match = re.search(r"(?:^|;\s*)p=([a-zA-Z]+)", record, re.IGNORECASE)
    p_val = p_match.group(1).lower() if p_match else "none"

    if p_val == "reject":
        strength = "strict"
    elif p_val == "quarantine":
        strength = "moderate"
    elif p_val == "none":
        strength = "weak"
    else:
        strength = "weak"

    pct_match = re.search(r"(?:^|;\s*)pct=(\d+)", record, re.IGNORECASE)
    pct_val: Optional[int] = int(pct_match.group(1)) if pct_match else None

    return {
        "present": True,
        "strength": strength,
        "pct": pct_val,
        "record": record,
    }


def summarize_dkim(dkim_hits: Dict[str, List[str]]) -> Dict[str, Any]:
    """Summarize discovered DKIM selectors (inconclusive by nature)."""
    return {
        "selectors_found": sorted(dkim_hits.keys()),
        "conclusive": False,
        "note": "absence at these selectors doesn't confirm DKIM isn't configured under a different selector name",
    }


def score_mta_sts(
    mta_sts_records: List[str],
    policy_file: Optional[str] = None,
    policy_error: Optional[str] = None,
) -> Dict[str, Any]:
    """Score MTA-STS posture (RFC 8461) based on DNS TXT and optional policy file."""
    matching = [r.strip() for r in mta_sts_records if r.strip().lower().startswith("v=stsv1")]
    if not matching:
        return {"present": False, "mode": "missing"}

    record = matching[0]
    id_match = re.search(r"(?:^|;\s*)id=([a-zA-Z0-9]+)", record, re.IGNORECASE)
    id_val = id_match.group(1) if id_match else None

    res: Dict[str, Any] = {
        "present": True,
        "id": id_val,
        "record": record,
        "mode": "unknown",
    }

    if policy_file:
        mode_match = re.search(r"^mode:\s*([a-zA-Z]+)", policy_file, re.MULTILINE | re.IGNORECASE)
        max_age_match = re.search(r"^max_age:\s*(\d+)", policy_file, re.MULTILINE | re.IGNORECASE)
        mx_matches = re.findall(r"^mx:\s*([^\s]+)", policy_file, re.MULTILINE | re.IGNORECASE)

        mode_val = mode_match.group(1).lower() if mode_match else "unknown"
        res["mode"] = mode_val
        res["max_age"] = int(max_age_match.group(1)) if max_age_match else None
        res["mx"] = mx_matches
        res["policy_file_present"] = True
    elif policy_error:
        res["policy_file_present"] = False
        res["policy_file_error"] = policy_error

    return res


def score_tls_rpt(tls_rpt_records: List[str]) -> Dict[str, Any]:
    """Score SMTP TLS Reporting posture (RFC 8460)."""
    matching = [r.strip() for r in tls_rpt_records if r.strip().lower().startswith("v=tlsrptv1")]
    if not matching:
        return {"present": False}

    record = matching[0]
    rua_match = re.search(r"(?:^|;\s*)rua=([^;\s]+)", record, re.IGNORECASE)
    rua_val = rua_match.group(1) if rua_match else None

    return {
        "present": True,
        "rua": rua_val,
        "record": record,
    }


def parse_result(raw: RawEmailAuthResult, target: str) -> Dict[str, Any]:
    """Combine SPF, DMARC, DKIM, MTA-STS, and TLS-RPT assessments into a structured result."""
    return {
        "target": target,
        "spf": score_spf(raw.spf_txt_records),
        "dmarc": score_dmarc(raw.dmarc_txt_records),
        "dkim": summarize_dkim(raw.dkim_hits),
        "mta_sts": score_mta_sts(
            raw.mta_sts_txt_records,
            raw.mta_sts_policy_file,
            raw.mta_sts_policy_error,
        ),
        "tls_rpt": score_tls_rpt(raw.tls_rpt_txt_records),
    }
