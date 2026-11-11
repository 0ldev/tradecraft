"""
Tests whether one SSH private key authenticates against a bounded list
of candidate hosts -- one non-interactive attempt per host, no
retries, no password fallback. Classified destructive: false -- unlike
a password guess, a declined SSH key carries no account-lockout risk.
Belongs to profile 'post-exploitation'.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.ssh_key_reuse_probe import execute as reuse_execute
from tradecraft.adapters.ssh_key_reuse_probe import parse as reuse_parse
from tradecraft.tools.base import Tool


class SshKeyReuseProbe(Tool):
    tool_id = "ssh_key_reuse_probe"

    def is_available(self) -> bool:
        return reuse_execute.find_ssh_binary() is not None

    def run(
        self,
        private_key: str,
        ssh_user: str,
        targets: List[str],
    ) -> Dict[str, Any]:
        raw = reuse_execute.execute(
            private_key=private_key, ssh_user=ssh_user, targets=targets
        )
        return reuse_parse.parse_key_reuse_result(raw)

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        facts: List[Dict[str, Any]] = []
        for record in result.get("results", []):
            host = record.get("host")
            if not host:
                continue
            facts.append(
                {
                    "host": host,
                    "port": record.get("port") or 22,
                    "protocol": "ssh",
                    "ssh_key_reuse_auth_succeeded": bool(record.get("auth_succeeded")),
                    "ssh_key_reuse_shell_confirmed": bool(
                        record.get("confirmation_output_present")
                    ),
                }
            )
        return facts
