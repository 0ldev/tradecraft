"""
Cloud Identity Pool Probe tool: checks whether an AWS Cognito Identity
Pool grants unauthenticated visitors real temporary AWS credentials.
Glues config/tools/cloud_identity_pool_probe.yaml to
tradecraft.adapters.cloud_identity_pool_probe. destructive: true -- see
that YAML's description for why (a real identity record is created in
AWS's backend, the same reasoning auth_bootstrap's destructive
classification uses for a real public-facing registration flow).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from tradecraft.adapters.cloud_identity_pool_probe.execute import execute as pool_execute
from tradecraft.adapters.cloud_identity_pool_probe.parse import parse as pool_parse
from tradecraft.tools.base import Tool


class CloudIdentityPoolProbe(Tool):
    tool_id = "cloud_identity_pool_probe"

    def run(self, identity_pool_id: str, region: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        result = pool_execute(identity_pool_id=identity_pool_id, region=region, timeout=timeout)
        return pool_parse(result)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        facts: List[Dict[str, Any]] = []
        for attempt in result.get("attempts", []):
            region = attempt.get("region") or "unknown-region"
            fact: Dict[str, Any] = {
                "host": f"cognito-identity.{region}.amazonaws.com",
                "port": 443,
                "service": "aws-cognito-identity-pool",
                "state": "open",
            }
            if attempt.get("credentials_obtained"):
                fact["vulnerability"] = (
                    f"Identity Pool '{attempt['identity_pool_id']}' grants unauthenticated visitors "
                    "real temporary AWS credentials"
                )
                fact["severity"] = "critical"
            facts.append(fact)
        return facts
