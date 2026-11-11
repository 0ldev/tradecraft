"""
Pure parsing logic for cloud_metadata_credential_probe results.
Normalizes extracted credentials across AWS, GCP, and Azure into a unified
structured dictionary. No network calls or I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from tradecraft.adapters.cloud_metadata_credential_probe.execute import (
    HttpExchange,
    RawCredentialTheftResult,
)


def _serialize_exchange(ex: HttpExchange) -> Dict[str, Any]:
    return {
        "step": ex.step,
        "target_url": ex.target_url,
        "injected_url": ex.injected_url,
        "status_code": ex.status_code,
        "response_snippet": ex.response_text[:500] if ex.response_text else "",
        "error": ex.error,
    }


def _parse_aws_credentials(raw_json: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    access_key = data.get("AccessKeyId") or data.get("access_key_id")
    secret_key = data.get("SecretAccessKey") or data.get("secret_access_key")
    token = data.get("Token") or data.get("session_token")
    expiration = data.get("Expiration") or data.get("expiration")

    if access_key and secret_key:
        return {
            "access_key_id": access_key,
            "secret_access_key": secret_key,
            "session_token": token or "",
            "expiration": expiration or "",
        }
    return None


def _parse_gcp_credentials(raw_json: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    token = data.get("access_token")
    token_type = data.get("token_type", "Bearer")
    expires_in = data.get("expires_in")

    if token:
        return {
            "token": token,
            "token_type": token_type,
            "expires_in": expires_in,
        }
    return None


def _parse_azure_credentials(raw_json: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    token = data.get("access_token")
    token_type = data.get("token_type", "Bearer")
    resource = data.get("resource")
    expires_on = data.get("expires_on")
    client_id = data.get("client_id")

    if token:
        return {
            "token": token,
            "token_type": token_type,
            "resource": resource or "",
            "expires_on": expires_on or "",
            "client_id": client_id or "",
        }
    return None


def parse(raw: RawCredentialTheftResult) -> Dict[str, Any]:
    """Parse raw execution results into a clean, normalized dictionary."""
    output: Dict[str, Any] = {
        "target": raw.target,
        "provider": raw.provider,
        "inject_location": raw.inject_location,
        "credentials_obtained": False,
        "role_name": raw.role_name,
        "credentials": {},
        "summary": "",
        "exchanges": [_serialize_exchange(ex) for ex in raw.exchanges],
        "error": raw.error,
    }

    if raw.error:
        output["summary"] = f"Execution halted with error: {raw.error}"
        return output

    creds: Optional[Dict[str, Any]] = None

    if raw.provider == "aws" or (raw.provider == "auto" and raw.role_name):
        creds = _parse_aws_credentials(raw.raw_credential_json)
        if creds:
            output["provider"] = "aws"
            output["credentials_obtained"] = True
            output["credentials"] = creds
            role_desc = f" for role '{raw.role_name}'" if raw.role_name else ""
            output["summary"] = (
                f"Successfully extracted temporary AWS credentials{role_desc} "
                f"(AccessKeyId: {creds['access_key_id']})"
            )
            return output

    if raw.provider in ("gcp", "auto"):
        creds = _parse_gcp_credentials(raw.raw_credential_json)
        if creds:
            output["provider"] = "gcp"
            output["credentials_obtained"] = True
            output["credentials"] = creds
            output["summary"] = "Successfully extracted GCP service account OAuth token"
            return output

    if raw.provider in ("azure", "auto"):
        creds = _parse_azure_credentials(raw.raw_credential_json)
        if creds:
            output["provider"] = "azure"
            output["credentials_obtained"] = True
            output["credentials"] = creds
            output["summary"] = "Successfully extracted Azure Managed Identity token"
            return output

    # If no credentials obtained, build an informative diagnostic summary
    if raw.exchanges:
        last_ex = raw.exchanges[-1]
        if last_ex.status_code == 403:
            output["summary"] = (
                f"Metadata service reached on step '{last_ex.step}' but returned 403 Forbidden "
                "(IMDSv2 or metadata protection may be enforced)"
            )
        elif last_ex.status_code == 404:
            output["summary"] = (
                f"Metadata endpoint on step '{last_ex.step}' returned 404 Not Found"
            )
        elif last_ex.error:
            output["summary"] = f"Request on step '{last_ex.step}' failed: {last_ex.error}"
        else:
            status_desc = f"status {last_ex.status_code}" if last_ex.status_code else "no response"
            output["summary"] = f"Metadata query failed to produce valid credentials ({status_desc})"
    else:
        output["summary"] = "No HTTP exchanges took place"

    return output
