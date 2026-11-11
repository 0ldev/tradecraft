"""
Pure parsing for azure_tenant_recon: turns the raw discovery and username
checks into the dict the model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.azure_tenant_recon.execute import RawAzureTenantResult


def parse_azure_tenant_result(raw: RawAzureTenantResult) -> Dict[str, Any]:
    if raw.error:
        return {"domain": raw.domain, "error": raw.error}
    if not raw.is_azure_ad:
        return {
            "domain": raw.domain,
            "is_azure_ad": False,
            "reason": "domain is not backed by Azure AD / Entra ID",
        }

    out: Dict[str, Any] = {
        "domain": raw.domain,
        "is_azure_ad": True,
        "tenant_id": raw.tenant_id,
        "domain_namespace_type": raw.domain_namespace_type,
        "existing_usernames": [c.username for c in raw.checks if c.exists is True],
        "checked_count": len(raw.checks),
    }
    namespace_types = {c.username: c.namespace_type for c in raw.checks if c.namespace_type}
    if namespace_types:
        out["namespace_types"] = namespace_types
    unresolved = [
        {"username": c.username, "if_exists_result": c.if_exists_result}
        for c in raw.checks
        if c.exists is None and c.throttle_status is None and c.error is None
    ]
    if unresolved:
        out["unresolved_usernames"] = unresolved
    errored = [
        {"username": c.username, "error": c.error} for c in raw.checks if c.error
    ]
    if errored:
        out["errors"] = errored
    return out
