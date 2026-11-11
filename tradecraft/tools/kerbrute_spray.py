from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.kerbrute_spray import execute as spray_execute
from tradecraft.adapters.kerbrute_spray import parse as spray_parse
from tradecraft.policy.credential_budget import CredentialLedger
from tradecraft.tools.base import Tool


class KerbruteSpray(Tool):
    tool_id = "kerbrute_spray"

    def __init__(self, ledger: Optional[CredentialLedger] = None) -> None:
        self._ledger = ledger if ledger is not None else CredentialLedger()

    def is_available(self) -> bool:
        return spray_execute.find_binary() is not None

    def run(
        self,
        domain: str,
        password: str,
        user_wordlist: str = "kerbrute-usernames",
        dc_ip: str = "",
    ) -> Dict[str, Any]:
        endpoint = domain.strip()
        attempts_allowed, capped = self._ledger.allow(endpoint, 1)
        if attempts_allowed < 1:
            return {
                "domain": domain,
                "password": "<redacted>",
                "valid_credentials": [],
                "total_valid": 0,
                "budget": {
                    "total_budget": self._ledger.total_budget,
                    "remaining_after_this_call": self._ledger.remaining(endpoint),
                    "capped_by_budget": True,
                },
                "error": (
                    f"account_lockout_risk budget for domain {domain!r} is spent "
                    f"({self._ledger.total_budget} spray rounds already run this "
                    "engagement) -- no further kerbrute_spray calls against this "
                    "domain this engagement"
                ),
            }

        raw = spray_execute.execute(
            domain=domain,
            password=password,
            user_wordlist=user_wordlist,
            dc_ip=dc_ip,
        )
        self._ledger.record(endpoint, raw.attempts_run)
        parsed = spray_parse.parse_kerbrute_spray_output(raw)
        parsed["budget"] = {
            "total_budget": self._ledger.total_budget,
            "remaining_after_this_call": self._ledger.remaining(endpoint),
            "capped_by_budget": capped,
        }
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "domain": domain,
                "valid_credentials": parsed.get("valid_credentials", []),
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        domain = params.get("domain") or result.get("domain", "")
        full = result.pop("_full_evidence", None)
        if not domain or full is None:
            return None
        return domain, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        domain = params.get("domain") or result.get("domain", "")
        valid = result.get("valid_credentials", [])
        if not domain or not valid:
            return []
        return [
            {
                "host": domain,
                "port": 88,
                "valid_credentials_found": True,
                "valid_usernames": valid,
            }
        ]
