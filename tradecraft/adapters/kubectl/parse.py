"""
Pure parsing and token inspection for kubectl.
No subprocess or network I/O here.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RawKubectlResult:
    target: str = ""
    namespace: Optional[str] = None
    overprivileged: bool = False
    permissions: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


def parse_target_endpoint(target: str) -> str:
    """Normalize target string to hostname/IP:port without scheme."""
    target = target.strip()
    if target.startswith("https://"):
        target = target[len("https://") :]
    elif target.startswith("http://"):
        target = target[len("http://") :]
    return target.rstrip("/")


def parse_host_port(target: str, default_port: int = 6443) -> Tuple[str, int]:
    """Extract host and port from Kubernetes target string."""
    endpoint = parse_target_endpoint(target)
    parsed = urllib.parse.urlsplit(f"//{endpoint}")
    host = parsed.hostname or endpoint
    port = parsed.port or default_port
    return host, port


def namespace_from_token(token: str) -> Optional[str]:
    """Best-effort decode of a Kubernetes service-account JWT's own
    kubernetes.io/serviceaccount/namespace claim without signature verification.
    Returns None for non-JWT or opaque tokens."""
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + padding).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    ns = claims.get("kubernetes.io/serviceaccount/namespace")
    return ns if isinstance(ns, str) and ns else None


def parse_can_i_output(stdout: str) -> Tuple[bool, bool, List[Dict[str, Any]]]:
    """Parses `kubectl auth can-i --list` output (supports both tabular text and JSON).
    Returns (overprivileged, can_get_secrets, permissions)."""
    if not stdout or not stdout.strip():
        return False, False, []

    clean_stdout = stdout.strip()

    # 1. JSON parsing path (legacy / mock)
    if clean_stdout.startswith("{"):
        try:
            data = json.loads(clean_stdout)
            status = data.get("status")
            if isinstance(status, dict) and isinstance(status.get("resourceRules"), list):
                resource_rules = status["resourceRules"]
            elif isinstance(data.get("resourceRules"), list):
                resource_rules = data["resourceRules"]
            else:
                resource_rules = []

            overprivileged = False
            can_get_secrets = False

            for rule in resource_rules:
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])

                if "*" in verbs or "*" in resources:
                    overprivileged = True
                    can_get_secrets = True
                elif "secrets" in resources and any(v in ("get", "list", "*") for v in verbs):
                    can_get_secrets = True

            return overprivileged, can_get_secrets, resource_rules
        except Exception:
            pass

    # 2. Tabular text parsing path (real kubectl output)
    resource_rules: List[Dict[str, Any]] = []
    overprivileged = False
    can_get_secrets = False

    for line in clean_stdout.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("resources"):
            continue

        m_brackets = re.findall(r"\[(.*?)\]", line)
        if m_brackets:
            verbs = m_brackets[-1].split()
            tokens = line.split()
            resource = tokens[0] if tokens else ""
            rule = {"resources": [resource], "verbs": verbs}
            resource_rules.append(rule)

            if "*" in verbs or resource in ("*", "*.*"):
                overprivileged = True
                can_get_secrets = True
            elif "secrets" in resource and any(v in ("get", "list", "*") for v in verbs):
                can_get_secrets = True

    return overprivileged, can_get_secrets, resource_rules


def parse_secrets_output(stdout: str) -> List[Dict[str, Any]]:
    """Parses `kubectl get secrets -o json` output into decoded secret items."""
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except Exception:
        return []

    secrets: List[Dict[str, Any]] = []
    items = data.get("items", []) if isinstance(data, dict) else []

    for item in items:
        metadata = item.get("metadata", {})
        namespace = metadata.get("namespace", "default")
        name = metadata.get("name", "")
        secret_data = item.get("data", {})

        for key, encoded_value in secret_data.items():
            try:
                decoded_val = base64.b64decode(encoded_value).decode("utf-8", errors="replace")
            except Exception:
                decoded_val = encoded_value

            secrets.append(
                {
                    "namespace": namespace,
                    "name": name,
                    "key": key,
                    "value": decoded_val,
                }
            )

    return secrets


def parse_kubectl_result(raw: RawKubectlResult) -> Dict[str, Any]:
    """Transforms raw probe result into structured output."""
    return {
        "target": raw.target,
        "namespace": raw.namespace,
        "overprivileged": raw.overprivileged,
        "permissions_count": len(raw.permissions),
        "permissions": raw.permissions[:20],  # cap permissions in prompt
        "secrets_count": len(raw.secrets),
        "secrets": raw.secrets[:15],  # cap secrets in prompt
        "error": raw.error,
    }
