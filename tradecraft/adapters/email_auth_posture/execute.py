"""
Raw execution for email_auth_posture: queries DNS TXT records for SPF, DMARC,
DKIM, MTA-STS, and TLS-RPT via the existing dnsx adapter. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

from tradecraft.adapters.dnsx import execute as dnsx_execute
from tradecraft.adapters.dnsx import parse as dnsx_parse

DEFAULT_DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "dkim", "k1", "mail")


@dataclass
class RawEmailAuthResult:
    target: str = ""
    spf_txt_records: List[str] = field(default_factory=list)
    dmarc_txt_records: List[str] = field(default_factory=list)
    dkim_hits: Dict[str, List[str]] = field(default_factory=dict)  # selector -> TXT records found
    mta_sts_txt_records: List[str] = field(default_factory=list)
    tls_rpt_txt_records: List[str] = field(default_factory=list)
    mta_sts_policy_file: Optional[str] = None
    mta_sts_policy_error: Optional[str] = None
    error: Optional[str] = None


def normalize_domain(target: str) -> str:
    """Extract clean domain/hostname from a target string."""
    t = target.strip()
    if not t:
        return ""
    if "://" in t:
        parsed = urllib.parse.urlsplit(t)
        host = parsed.hostname or parsed.netloc.split(":")[0]
    else:
        host = t.split("/")[0].split(":")[0].strip()
    return re.sub(r"[^a-zA-Z0-9.\-_]", "", host).strip(".-")


def execute(
    target: str,
    dkim_selectors: Optional[List[str]] = None,
    timeout: int = 60,
) -> RawEmailAuthResult:
    domain = normalize_domain(target)
    if not domain:
        return RawEmailAuthResult(error="empty or invalid target domain")

    selectors = dkim_selectors or list(DEFAULT_DKIM_SELECTORS)
    clean_selectors = [re.sub(r"[^a-zA-Z0-9.\-_]", "", s).strip(".-") for s in selectors]
    clean_selectors = [s for s in clean_selectors if s]

    hostnames = [
        domain,
        f"_dmarc.{domain}",
        f"_mta-sts.{domain}",
        f"_smtp._tls.{domain}",
    ] + [f"{s}._domainkey.{domain}" for s in clean_selectors]

    raw_dnsx = dnsx_execute.execute(target=",".join(hostnames), query_type="txt", timeout=timeout)
    if raw_dnsx.error:
        return RawEmailAuthResult(target=domain, error=raw_dnsx.error)

    records = dnsx_parse.parse_dns_records(raw_dnsx.stdout)

    spf_txt_records: List[str] = []
    dmarc_txt_records: List[str] = []
    dkim_hits: Dict[str, List[str]] = {}
    mta_sts_txt_records: List[str] = []
    tls_rpt_txt_records: List[str] = []

    target_lower = domain.lower()
    dmarc_host_lower = f"_dmarc.{domain}".lower()
    mta_sts_host_lower = f"_mta-sts.{domain}".lower()
    tls_rpt_host_lower = f"_smtp._tls.{domain}".lower()
    selector_host_map = {f"{s}._domainkey.{domain}".lower(): s for s in clean_selectors}

    for record in records:
        host = (record.get("host") or "").lower()
        txts = record.get("txt", [])
        if not txts:
            continue

        if host == target_lower:
            for txt in txts:
                if txt.lower().startswith("v=spf1"):
                    spf_txt_records.append(txt)
        elif host == dmarc_host_lower:
            dmarc_txt_records.extend(txts)
        elif host == mta_sts_host_lower:
            mta_sts_txt_records.extend(txts)
        elif host == tls_rpt_host_lower:
            tls_rpt_txt_records.extend(txts)
        elif host in selector_host_map:
            sel = selector_host_map[host]
            dkim_hits[sel] = txts

    # If MTA-STS TXT record exists, fetch policy file if requests available
    mta_sts_policy_file: Optional[str] = None
    mta_sts_policy_error: Optional[str] = None
    has_sts_record = any(r.strip().lower().startswith("v=stsv1") for r in mta_sts_txt_records)

    if has_sts_record and requests is not None:
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            resp = requests.get(
                policy_url,
                timeout=5,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"},
            )
            if resp.status_code == 200:
                mta_sts_policy_file = (resp.text or "")[:4000]
            else:
                mta_sts_policy_error = f"HTTP {resp.status_code}"
        except Exception as exc:
            mta_sts_policy_error = str(exc)

    return RawEmailAuthResult(
        target=domain,
        spf_txt_records=spf_txt_records,
        dmarc_txt_records=dmarc_txt_records,
        dkim_hits=dkim_hits,
        mta_sts_txt_records=mta_sts_txt_records,
        tls_rpt_txt_records=tls_rpt_txt_records,
        mta_sts_policy_file=mta_sts_policy_file,
        mta_sts_policy_error=mta_sts_policy_error,
    )
