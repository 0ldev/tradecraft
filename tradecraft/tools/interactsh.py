from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.interactsh.execute import (
    DEFAULT_POLL_INTERVAL,
    DEFAULT_SERVER,
    execute as run_interactsh,
)
from tradecraft.tools.base import Tool


class Interactsh(Tool):
    tool_id = "interactsh"

    def run(
        self,
        action: str,
        server: Optional[str] = None,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> Dict[str, Any]:
        result = run_interactsh(
            action=action,
            server=server or DEFAULT_SERVER,
            poll_interval=poll_interval,
        )

        interactions = result.get("interactions", [])
        if len(interactions) > 10:
            result["interactions"] = interactions[:10]
            result["omitted_interactions"] = len(interactions) - 10
            result["note"] = (
                f"{len(interactions) - 10} more interactions omitted to conserve context. "
                "Use search_evidence to inspect details."
            )

        if interactions:
            result["_full_evidence"] = {
                "action": action,
                "payload_domain": result.get("payload_domain", ""),
                "total_interactions": len(interactions),
                "interactions": interactions,
            }

        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        if full is None:
            return None
        domain = result.get("payload_domain") or "interactsh"
        return domain, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        interactions = result.get("interactions", [])
        if not interactions:
            return []

        facts: List[Dict[str, Any]] = []
        for item in interactions:
            # after_domain_generated is explicitly False -> this
            # interaction's own timestamp precedes the current payload
            # domain's creation, so it cannot have been caused by a
            # request sent during this engagement. Never record it as
            # a confirmed detection. (Missing/None -- unparseable
            # timestamp -- still counts as detected, since absence of
            # proof isn't proof of staleness.)
            if item.get("after_domain_generated") is False:
                continue
            remote_ip = item.get("remote_address", "")
            if remote_ip and ":" in remote_ip:
                remote_ip = remote_ip.split(":")[0]
            if remote_ip:
                fact: Dict[str, Any] = {
                    "host": remote_ip,
                    "port": 0,
                    "oast_interaction_detected": True,
                    "oast_protocol": item.get("protocol", "unknown"),
                }
                if result.get("evidence_id"):
                    fact["evidence"] = result["evidence_id"]
                facts.append(fact)
        return facts
