"""
Parsing logic for cloud_identity_pool_probe results. Pure functions,
no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cloud_identity_pool_probe.execute import CloudIdentityPoolResult


def parse(result: CloudIdentityPoolResult) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "target": result.target,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
        "error": result.error,
        "attempts": [],
    }

    findings: List[str] = []
    for attempt in result.attempts:
        output["attempts"].append({
            "identity_pool_id": attempt.identity_pool_id,
            "region": attempt.region,
            "status": attempt.status,
            "identity_id": attempt.identity_id,
            "credentials_obtained": attempt.credentials_obtained,
            "access_key_id": attempt.access_key_id,
            "secret_key": attempt.secret_key,
            "session_token": attempt.session_token,
            "error": attempt.error,
        })
        if attempt.vulnerable:
            findings.append(
                f"Identity Pool '{attempt.identity_pool_id}' grants unauthenticated visitors real "
                f"temporary AWS credentials (AccessKeyId {attempt.access_key_id})"
            )

    output["findings"] = findings
    return output
