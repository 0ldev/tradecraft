"""
Pure parsing for jenkins_unauth_probe. No I/O here.
"""
from __future__ import annotations

from typing import Any, Dict


def parse(raw) -> Dict[str, Any]:
    if not raw.is_jenkins:
        return {"target": raw.target, "base_url": raw.base_url, "is_jenkins": False, "error": raw.error}

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "is_jenkins": True,
        "jenkins_version": raw.jenkins_version,
        "whoami_authenticated": raw.whoami_body.get("authenticated") if raw.whoami_body else None,
        "whoami_name": (
            (raw.whoami_body.get("fullName") or raw.whoami_body.get("id")) if raw.whoami_body else None
        ),
        "script_console_reachable": raw.script_console_reachable,
        "manage_panel_reachable": raw.manage_reachable,
        "job_count": len(raw.api_json.get("jobs", [])) if raw.api_json else 0,
        "mode": raw.api_json.get("mode") if raw.api_json else None,
        "error": None,
    }
