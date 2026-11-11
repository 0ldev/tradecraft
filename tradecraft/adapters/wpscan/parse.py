"""
Pure parsing functions for wpscan output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0].split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_wpscan_output(stdout: str = "") -> Dict[str, Any]:
    """
    Parses wpscan JSON output from stdout into structured results.
    """
    if not stdout or not stdout.strip():
        return {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "interesting_findings": [],
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "total_plugins": 0,
            "total_users": 0,
            "error": "Empty output from wpscan",
        }

    try:
        data = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "interesting_findings": [],
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "total_plugins": 0,
            "total_users": 0,
            "error": "wpscan output was not valid JSON",
        }

    if not isinstance(data, dict):
        return {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "interesting_findings": [],
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "total_plugins": 0,
            "total_users": 0,
        }

    if data.get("scan_aborted"):
        return {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "interesting_findings": [],
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "total_plugins": 0,
            "total_users": 0,
            "error": f"wpscan scan aborted: {data.get('scan_aborted')}",
        }

    vulnerabilities: List[Dict[str, Any]] = []

    wp_version_info: Optional[Dict[str, Any]] = None
    v_data = data.get("version")
    if isinstance(v_data, dict) and v_data.get("number"):
        wp_version_info = {
            "number": v_data.get("number"),
            "status": v_data.get("status", "unknown"),
        }
        for v in v_data.get("vulnerabilities", []):
            if isinstance(v, dict):
                vulnerabilities.append({
                    "type": "core",
                    "title": v.get("title", ""),
                    "fixed_in": v.get("fixed_in"),
                    "references": v.get("references", {}),
                })

    theme_info: Optional[Dict[str, Any]] = None
    t_data = data.get("main_theme")
    if isinstance(t_data, dict) and (t_data.get("slug") or t_data.get("style_name")):
        t_ver = t_data.get("version", {})
        ver_number = t_ver.get("number") if isinstance(t_ver, dict) else str(t_ver)
        theme_info = {
            "slug": t_data.get("slug") or t_data.get("style_name"),
            "version": ver_number,
            "location": t_data.get("location"),
        }
        for v in t_data.get("vulnerabilities", []):
            if isinstance(v, dict):
                vulnerabilities.append({
                    "type": "theme",
                    "target": theme_info["slug"],
                    "title": v.get("title", ""),
                    "fixed_in": v.get("fixed_in"),
                    "references": v.get("references", {}),
                })

    plugins: List[Dict[str, Any]] = []
    p_data = data.get("plugins", {})
    if isinstance(p_data, dict):
        for slug, p_entry in p_data.items():
            if not isinstance(p_entry, dict):
                continue
            ver_obj = p_entry.get("version", {})
            p_ver = ver_obj.get("number") if isinstance(ver_obj, dict) else str(ver_obj)
            p_vulns = p_entry.get("vulnerabilities", [])
            plugin_dict = {
                "slug": slug,
                "version": p_ver,
                "location": p_entry.get("location"),
                "vulnerabilities_count": len(p_vulns) if isinstance(p_vulns, list) else 0,
            }
            plugins.append(plugin_dict)
            if isinstance(p_vulns, list):
                for v in p_vulns:
                    if isinstance(v, dict):
                        vulnerabilities.append({
                            "type": "plugin",
                            "target": slug,
                            "title": v.get("title", ""),
                            "fixed_in": v.get("fixed_in"),
                            "references": v.get("references", {}),
                        })

    users: List[str] = []
    u_data = data.get("users", {})
    if isinstance(u_data, dict):
        users.extend(u_data.keys())
    elif isinstance(u_data, list):
        for u in u_data:
            if isinstance(u, dict) and u.get("name"):
                users.append(u["name"])
            elif isinstance(u, str):
                users.append(u)

    interesting: List[Dict[str, Any]] = []
    for item in data.get("interesting_findings", []):
        if not isinstance(item, dict):
            continue
        interesting.append({
            "url": item.get("url", ""),
            "to_s": item.get("to_s", ""),
            "type": item.get("type", ""),
        })

    is_wordpress = bool(wp_version_info or theme_info or plugins or interesting)

    return {
        "is_wordpress": is_wordpress,
        "version": wp_version_info,
        "theme": theme_info,
        "plugins": plugins,
        "users": users,
        "interesting_findings": interesting,
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len(vulnerabilities),
        "total_plugins": len(plugins),
        "total_users": len(users),
    }
