"""
Self-registration and login using disposable throwaway credentials.
Classified as destructive: true.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, Tuple

from tradecraft.adapters.auth_bootstrap import execute as auth_execute
from tradecraft.tools.base import Tool


class AuthBootstrap(Tool):
    tool_id = "auth_bootstrap"

    def run(
        self,
        target: str,
        register_path: str = "",
        login_path: str = "",
    ) -> Dict[str, Any]:
        raw = auth_execute.execute(
            target=target,
            register_path=register_path,
            login_path=login_path,
        )
        return {
            "target": target,
            "registered": raw.registered,
            "session_token": raw.session_token,
            "email_used": raw.email_used,
            "registration_endpoint": raw.registration_endpoint,
            "login_endpoint": raw.login_endpoint,
            "error": raw.error,
        }

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        token = result.get("session_token")
        if not target or not token:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
        host = parsed.hostname or target
        return host, {
            "target": target,
            "email_used": result.get("email_used"),
            "session_token": token,
            "registration_endpoint": result.get("registration_endpoint"),
            "login_endpoint": result.get("login_endpoint"),
        }
