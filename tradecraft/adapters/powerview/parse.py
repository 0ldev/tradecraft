"""
Parsing logic for powerview Active Directory enumeration output.
Pure functions, no I/O, no subprocess calls.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class RawPowerViewResult:
    target: str = ""
    domain: str = ""
    query: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


_IGNORE_PATTERNS = [
    re.compile(r"^Logging directory is set to\b", re.IGNORECASE),
    re.compile(r"^\[Formatter\]\b", re.IGNORECASE),
    re.compile(r"^\[\*\]\b"),
    re.compile(r"^\[-\]\b"),
    re.compile(r"^\[\+\]\b"),
    re.compile(r"^\[!\]\b"),
]

_ERROR_INDICATORS = [
    "connection refused",
    "socket connection error",
    "ldap socket error",
    "ldapsocketopenerror",
    "ldapbinderror",
    "authentication to domain",
    "invalidcredentials",
    "timed out",
    "not found on path",
    "name or service not known",
]

_KEY_VAL_REGEX = re.compile(r"^([a-zA-Z0-9_\-\.]+)\s*:\s*(.*)$")


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


def parse_powerview_blocks(output: str) -> List[Dict[str, Any]]:
    """
    Parses standard PowerView key-value block output into a list of entry dicts.
    Each block represents an Active Directory object, with attributes separated by newlines.
    Multiple values under the same attribute (indented continuation lines) are stored as lists.
    """
    if not output or not output.strip():
        return []

    entries: List[Dict[str, Any]] = []
    current_entry: Dict[str, Any] = {}
    current_attr: Optional[str] = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()

        # Skip banner or log lines
        if any(pat.search(line.strip()) for pat in _IGNORE_PATTERNS):
            continue

        if not line.strip():
            if current_entry:
                entries.append(current_entry)
                current_entry = {}
                current_attr = None
            continue

        match = _KEY_VAL_REGEX.match(line)
        if match:
            attr = match.group(1).strip()
            val = match.group(2).strip()
            current_attr = attr
            current_entry[attr] = val
        elif current_attr and line.startswith(" "):
            # Indented continuation line under current attribute
            continuation_val = line.strip()
            if continuation_val:
                existing = current_entry.get(current_attr)
                if isinstance(existing, list):
                    existing.append(continuation_val)
                elif isinstance(existing, str):
                    if existing:
                        current_entry[current_attr] = [existing, continuation_val]
                    else:
                        current_entry[current_attr] = continuation_val
                else:
                    current_entry[current_attr] = [continuation_val]

    if current_entry:
        entries.append(current_entry)

    return entries


def extract_query_insights(query: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates structured summaries according to the query type."""
    q_lower = query.lower()
    insights: Dict[str, Any] = {
        "total_count": len(entries),
    }

    if "user" in q_lower:
        users: List[str] = []
        admin_users: List[str] = []
        kerberoastable: List[str] = []

        for entry in entries:
            name = entry.get("sAMAccountName") or entry.get("name") or entry.get("cn") or ""
            if name:
                users.append(name)

            admin_count = str(entry.get("adminCount", "")).strip()
            member_of = entry.get("memberOf", [])
            member_of_str = str(member_of).lower()
            if admin_count == "1" or "domain admins" in member_of_str or "administrators" in member_of_str:
                if name:
                    admin_users.append(name)

            spn = entry.get("servicePrincipalName")
            if spn:
                if name:
                    kerberoastable.append(name)

        insights["users"] = sorted(set(users))
        if admin_users:
            insights["admin_users"] = sorted(set(admin_users))
        if kerberoastable:
            insights["kerberoastable_users"] = sorted(set(kerberoastable))

    elif "group" in q_lower:
        groups: List[str] = []
        admin_groups: List[str] = []

        for entry in entries:
            name = entry.get("sAMAccountName") or entry.get("cn") or entry.get("name") or ""
            if name:
                groups.append(name)
            if "admin" in name.lower():
                admin_groups.append(name)

        insights["groups"] = sorted(set(groups))
        if admin_groups:
            insights["admin_groups"] = sorted(set(admin_groups))

    elif "computer" in q_lower:
        computers: List[str] = []
        operating_systems: List[str] = []

        for entry in entries:
            name = entry.get("dNSHostName") or entry.get("sAMAccountName") or entry.get("name") or ""
            if name:
                computers.append(name)
            os_name = entry.get("operatingSystem")
            if os_name and isinstance(os_name, str):
                operating_systems.append(os_name.strip())

        insights["computers"] = sorted(set(computers))
        if operating_systems:
            insights["operating_systems"] = sorted(set(operating_systems))

    elif "trust" in q_lower:
        trusts: List[str] = []
        for entry in entries:
            tname = entry.get("TargetName") or entry.get("TrustPartner") or entry.get("name") or ""
            if tname:
                trusts.append(tname)
        insights["trusts"] = sorted(set(trusts))

    elif "controller" in q_lower:
        dcs: List[str] = []
        for entry in entries:
            dc_name = entry.get("dNSHostName") or entry.get("Name") or entry.get("name") or ""
            if dc_name:
                dcs.append(dc_name)
        insights["domain_controllers"] = sorted(set(dcs))

    # Exact-token match, not a substring check: "domain" alone would also
    # match other real PowerView cmdlets whose output has nothing to do
    # with the domain object itself (Get-DomainObject, Get-DomainOU,
    # Get-DomainPolicy, etc.), mislabeling an unrelated entry's objectSid
    # as the domain SID. Must also stay after the trust/controller
    # branches: Get-DomainTrust/Get-DomainController's first token is
    # "get-domaintrust"/"get-domaincontroller", not "get-domain", so this
    # check alone already excludes them -- the ordering is kept anyway as
    # defense in depth.
    elif q_lower.split()[:1] == ["get-domain"]:
        domain_sid = None
        for entry in entries:
            sid = entry.get("objectSid")
            if sid and isinstance(sid, str):
                domain_sid = sid.strip()
                break
        if domain_sid:
            insights["domain_sid"] = domain_sid

    return insights


def detect_powerview_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects connectivity, authentication, or protocol errors in output."""
    combined = f"{stdout}\n{stderr}".lower()
    for ind in _ERROR_INDICATORS:
        if ind in combined:
            for line in f"{stdout}\n{stderr}".splitlines():
                if ind in line.lower():
                    return line.strip()
            return f"PowerView error detected: {ind}"
    return None


def parse_powerview_result(raw: RawPowerViewResult, max_entries_display: int = 50) -> Dict[str, Any]:
    """
    Parses RawPowerViewResult into a structured dictionary suitable for model consumption.
    """
    error = raw.error
    if not error:
        detected_err = detect_powerview_error(raw.stdout, raw.stderr)
        if detected_err:
            error = detected_err

    entries = parse_powerview_blocks(raw.stdout)
    insights = extract_query_insights(raw.query, entries)

    status = "failed" if error else "success"

    result: Dict[str, Any] = {
        "target": raw.target,
        "domain": raw.domain,
        "query": raw.query,
        "status": status,
        "total_entries": len(entries),
        "entries": entries[:max_entries_display],
        "insights": insights,
    }

    if len(entries) > max_entries_display:
        result["truncated"] = True
        result["note"] = f"Displaying first {max_entries_display} of {len(entries)} entries. Full entries saved in evidence."

    # Store full entries internally for evidence extraction before stripping
    result["_all_entries"] = entries

    if error:
        result["error"] = error

    return result
