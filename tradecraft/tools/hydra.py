"""
Bounded credential brute-forcing. See docs/policy.md for the
account_lockout_risk budget this tool shares with kerbrute_spray.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.hydra import execute as hydra_execute
from tradecraft.adapters.hydra import parse as hydra_parse
from tradecraft.policy.credential_budget import CredentialLedger
from tradecraft.tools.base import Tool


class Hydra(Tool):
    tool_id = "hydra"

    def __init__(self, ledger: Optional[CredentialLedger] = None) -> None:
        # The engagement loop passes a per-run ledger; a bare Hydra() (unit
        # tests, the registry's shared instance) gets its own fresh one.
        self._ledger = ledger if ledger is not None else CredentialLedger()

    def _endpoint(self, target: str, service: str, form_details: str) -> Tuple[str, int, str, str]:
        host, port = hydra_parse.parse_target_host_port(target)
        normalized = hydra_parse.normalize_service(service, target)
        form_path = form_details.split(":", 1)[0] if form_details else ""
        return host, port or 0, normalized, form_path

    def run(
        self,
        target: str,
        service: str = "",
        username: str = "",
        password_list: str = "",
        form_details: str = "",
        max_attempts: int = 50,
    ) -> Dict[str, Any]:
        endpoint = self._endpoint(target, service, form_details)
        attempts_allowed, capped = self._ledger.allow(endpoint, max_attempts)
        raw = hydra_execute.execute(
            target=target,
            service=service,
            username=username,
            password_list=password_list,
            form_details=form_details,
            max_attempts=attempts_allowed,
        )
        self._ledger.record(endpoint, raw.attempts_run)
        budget = {
            "requested": max_attempts,
            "ran": raw.attempts_run,
            "total_budget": self._ledger.total_budget,
            "remaining_after_this_call": self._ledger.remaining(endpoint),
            "capped_by_budget": capped,
        }
        if raw.error:
            return {
                "target": target,
                "service": raw.service,
                "credentials_found": [],
                "attempts_run": raw.attempts_run,
                "budget": budget,
                "error": raw.error,
            }

        creds = hydra_parse.parse_hydra_output(raw.stdout)
        # Hydra's success matching is not reliable on every login form (a
        # failure marker can fail to match and every guess looks like a
        # hit), so each hit is marked unverified until something else
        # confirms it.
        for c in creds:
            c["status"] = "unverified"
        res: Dict[str, Any] = {
            "target": target,
            "service": raw.service,
            "credentials_found": creds,
            "attempts_run": raw.attempts_run,
            "budget": budget,
        }
        if raw.returncode != 0 and not creds and raw.stderr.strip():
            res["error"] = raw.stderr.strip()
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        creds = result.get("credentials_found", [])
        if not target or not creds:
            return None
        host, _ = hydra_parse.parse_target_host_port(target)
        return host, {
            "target": target,
            "service": result.get("service"),
            "credentials_found": creds,
            "attempts_run": result.get("attempts_run"),
        }

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        creds = result.get("credentials_found", [])
        if not target or not creds:
            return []
        host, default_port = hydra_parse.parse_target_host_port(target)
        facts = []
        for c in creds:
            port = c.get("port") or default_port or 0
            login = c.get("login")
            pwd = c.get("password")
            # Recorded as a candidate, never as valid_credentials: nothing
            # has confirmed these logins yet.
            facts.append({
                "host": host,
                "port": int(port),
                "candidate_credentials": f"{login}:{pwd}",
            })
        return facts
