"""
Pure parsing functions for CMSeeK output.
Transforms raw CLI stdout and structured cms.json output into normalized findings.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cmseek.execute import RawCMSeeKResult


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extracts (host, port) from target URL or hostname."""
    t = target.strip()
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    parsed = urllib.parse.urlsplit(t)
    host = parsed.hostname or t
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _split_csv_entries(value: str) -> List[str]:
    """Splits trailing/comma-separated entries from CMSeeK output."""
    if not value or not isinstance(value, str):
        return []
    items = [x.strip() for x in value.split(",") if x.strip()]
    return items


def parse_cmseek_output(raw: RawCMSeeKResult) -> Dict[str, Any]:
    """Parses RawCMSeeKResult into a structured dictionary."""
    if raw.error:
        return {
            "target": raw.target_url,
            "cms_detected": False,
            "cms_id": "",
            "cms_name": "",
            "cms_version": "",
            "cms_url": "",
            "detection_method": "",
            "user_registration": "",
            "plugins": [],
            "themes": [],
            "users": [],
            "details": {},
            "error": raw.error,
        }

    json_data = raw.json_data or {}
    stdout = raw.stdout or ""

    cms_id = str(json_data.get("cms_id") or "").strip()
    cms_name = str(json_data.get("cms_name") or "").strip()
    cms_url = str(json_data.get("cms_url") or "").strip()
    detection_method = str(json_data.get("detection_param") or "").strip()
    user_reg = str(json_data.get("user_registration") or "").strip()

    # Version can appear in generic cms_version or cms-specific keys like wp_version
    cms_version = str(json_data.get("cms_version") or "").strip()
    if not cms_version and cms_id:
        ver_key = f"{cms_id}_version"
        if ver_key in json_data:
            cms_version = str(json_data[ver_key]).strip()

    plugins = []
    themes = []
    users = []

    for k, v in json_data.items():
        if k.endswith("_plugins"):
            plugins.extend(_split_csv_entries(v))
        elif k.endswith("_themes"):
            themes.extend(_split_csv_entries(v))
        elif k.endswith("_users"):
            users.extend(_split_csv_entries(v))

    # Fallback to stdout regex parsing if JSON was missing or incomplete
    if not cms_id and "CMS Detected, CMS ID:" in stdout:
        m = re.search(r"CMS Detected,\s*CMS ID:\s*([^\s,]+)(?:,\s*Detection method:\s*([^\s\r\n]+))?", stdout)
        if m:
            cms_id = m.group(1).strip()
            if m.group(2):
                detection_method = m.group(2).strip()

    if not cms_version and "Version Detected," in stdout:
        m = re.search(r"Version Detected,\s*(?:[A-Za-z0-9_\- ]+)?Version\s*([0-9a-zA-Z\.\-]+)", stdout)
        if m:
            cms_version = m.group(1).strip()

    if not users:
        found_users = re.findall(r"Found user from [^:]+:\s*([^\r\n]+)", stdout)
        if found_users:
            users = [u.strip() for u in found_users if u.strip()]

    cms_detected = bool(cms_id or cms_name)

    return {
        "target": raw.target_url,
        "cms_detected": cms_detected,
        "cms_id": cms_id,
        "cms_name": cms_name or cms_id,
        "cms_version": cms_version,
        "cms_url": cms_url,
        "detection_method": detection_method,
        "user_registration": user_reg,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "details": json_data,
    }
