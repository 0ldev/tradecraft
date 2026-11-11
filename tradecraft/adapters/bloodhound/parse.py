"""
Parsing logic for bloodhound Active Directory attack path graph output.
Pure functions, no I/O, no subprocess calls.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class RawBloodhoundResult:
    target: str = ""
    domain: str = ""
    collection_method: str = "DCOnly"
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    json_files: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


_ERROR_INDICATORS = [
    "connection refused",
    "lifetimetimeout",
    "the dns operation timed out",
    "failed to connect",
    "authentication failed",
    "invalid credentials",
    "timed out",
    "not found on path",
    "kdc_err",
    "error: unrecognized arguments",
]


def normalize_target_host(target: str) -> str:
    """Extracts raw hostname or IP from target string."""
    cleaned = target.strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.hostname or cleaned
    if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]
    return cleaned.strip("/[] ")


def parse_host_port(target: str, default_port: int = 389) -> Tuple[str, int]:
    """Parses host and port from target string."""
    host = normalize_target_host(target)
    cleaned = target.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.port:
            return host, parsed.port
    elif ":" in cleaned and cleaned.count(":") == 1:
        parts = cleaned.split(":")
        try:
            return parts[0].strip("/[] "), int(parts[1])
        except ValueError:
            pass
    return host, default_port


def detect_bloodhound_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects connectivity, DNS, or authentication errors in output."""
    combined = f"{stdout}\n{stderr}".lower()
    for ind in _ERROR_INDICATORS:
        if ind in combined:
            for line in f"{stdout}\n{stderr}".splitlines():
                if ind in line.lower():
                    return line.strip()
            return f"BloodHound error detected: {ind}"
    return None


def parse_bloodhound_json_files(json_files: Dict[str, str]) -> Dict[str, Any]:
    """
    Parses BloodHound JSON files (users, groups, computers, domains, etc.)
    and aggregates insights.
    """
    summary: Dict[str, Any] = {
        "users": [],
        "admin_users": [],
        "kerberoastable_users": [],
        "groups": [],
        "admin_groups": [],
        "computers": [],
        "operating_systems": [],
        "domains": [],
        "domain_sids": [],
        "trusts": [],
        "counts": {
            "users": 0,
            "groups": 0,
            "computers": 0,
            "domains": 0,
            "ous": 0,
            "gpos": 0,
        },
    }

    for fname, content in json_files.items():
        if not content or not content.strip():
            continue
        try:
            parsed = json.loads(content)
        except Exception:
            continue

        data_list = parsed.get("data", [])
        if not isinstance(data_list, list):
            continue

        fname_lower = fname.lower()
        if "users" in fname_lower:
            summary["counts"]["users"] = len(data_list)
            for item in data_list:
                props = item.get("Properties", {}) if isinstance(item, dict) else {}
                name = props.get("name") or props.get("samaccountname") or ""
                if name:
                    summary["users"].append(name)
                is_admin = props.get("admincount", False)
                if is_admin:
                    if name:
                        summary["admin_users"].append(name)
                spns = props.get("serviceprincipalnames", [])
                if spns and isinstance(spns, list) and len(spns) > 0:
                    if name:
                        summary["kerberoastable_users"].append(name)

        elif "groups" in fname_lower:
            summary["counts"]["groups"] = len(data_list)
            for item in data_list:
                props = item.get("Properties", {}) if isinstance(item, dict) else {}
                name = props.get("name") or ""
                if name:
                    summary["groups"].append(name)
                if props.get("admincount", False) or "admin" in name.lower():
                    if name:
                        summary["admin_groups"].append(name)

        elif "computers" in fname_lower:
            summary["counts"]["computers"] = len(data_list)
            for item in data_list:
                props = item.get("Properties", {}) if isinstance(item, dict) else {}
                name = props.get("name") or ""
                if name:
                    summary["computers"].append(name)
                os_name = props.get("operatingsystem")
                if os_name and isinstance(os_name, str):
                    summary["operating_systems"].append(os_name.strip())

        elif "domains" in fname_lower:
            summary["counts"]["domains"] = len(data_list)
            for item in data_list:
                props = item.get("Properties", {}) if isinstance(item, dict) else {}
                name = props.get("name") or props.get("domain") or ""
                if name:
                    summary["domains"].append(name)
                sid = item.get("ObjectIdentifier") if isinstance(item, dict) else None
                if sid and isinstance(sid, str):
                    summary["domain_sids"].append(sid.strip())
                trusts = item.get("Trusts", [])
                if isinstance(trusts, list):
                    for t in trusts:
                        tname = t.get("TargetName") or t.get("TargetDomainName") or ""
                        if tname:
                            summary["trusts"].append(tname)

        elif "ous" in fname_lower:
            summary["counts"]["ous"] = len(data_list)

        elif "gpos" in fname_lower:
            summary["counts"]["gpos"] = len(data_list)

    summary["users"] = sorted(set(summary["users"]))
    summary["admin_users"] = sorted(set(summary["admin_users"]))
    summary["kerberoastable_users"] = sorted(set(summary["kerberoastable_users"]))
    summary["groups"] = sorted(set(summary["groups"]))
    summary["admin_groups"] = sorted(set(summary["admin_groups"]))
    summary["computers"] = sorted(set(summary["computers"]))
    summary["operating_systems"] = sorted(set(summary["operating_systems"]))
    summary["domains"] = sorted(set(summary["domains"]))
    summary["domain_sids"] = sorted(set(summary["domain_sids"]))
    summary["trusts"] = sorted(set(summary["trusts"]))

    return summary


def parse_bloodhound_result(raw: RawBloodhoundResult, max_preview: int = 25) -> Dict[str, Any]:
    """
    Parses RawBloodhoundResult into a concise structured dictionary.
    """
    error = raw.error
    if not error:
        detected_err = detect_bloodhound_error(raw.stdout, raw.stderr)
        if detected_err and not raw.json_files:
            error = detected_err

    summary = parse_bloodhound_json_files(raw.json_files)
    total_objects = sum(summary["counts"].values())

    status = "failed" if (error and total_objects == 0) else "success"

    result: Dict[str, Any] = {
        "target": raw.target,
        "domain": raw.domain,
        "collection_method": raw.collection_method,
        "status": status,
        "total_objects_collected": total_objects,
        "counts": summary["counts"],
        "insights": {
            "users_sample": summary["users"][:max_preview],
            "admin_users": summary["admin_users"][:max_preview],
            "kerberoastable_users": summary["kerberoastable_users"][:max_preview],
            "groups_sample": summary["groups"][:max_preview],
            "admin_groups": summary["admin_groups"][:max_preview],
            "computers_sample": summary["computers"][:max_preview],
            "operating_systems": summary["operating_systems"],
            "domains": summary["domains"],
            "domain_sids": summary["domain_sids"],
            "trusts": summary["trusts"],
        },
        "files_generated": sorted(raw.json_files.keys()),
    }

    if error:
        result["error"] = error

    return result
