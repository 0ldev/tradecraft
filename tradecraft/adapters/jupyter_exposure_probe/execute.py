"""
Raw execution for jupyter_exposure_probe: detection-only fingerprinting of
an exposed Jupyter server or JupyterHub. Never creates a notebook, starts a
kernel, or executes code -- two anonymous GETs per service at most:

  Jupyter:     /api fingerprints the server; /api/kernels returning 200
               (even an empty list) proves the API is reachable without a
               token.
  JupyterHub:  /hub/api fingerprints the hub; /hub/api/users returning 200
               proves unauthenticated user listing.

No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_PORT = 8888


@dataclass
class RawJupyterResult:
    target: str = ""
    host: str = ""
    port: int = DEFAULT_PORT
    base_url: str = ""
    service: str = ""
    connected: bool = False
    version: str = ""
    auth_required: bool = False
    vulnerable: bool = False
    status: str = "unknown"
    kernels_listed: Optional[int] = None
    users_listed: Optional[int] = None
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


def split_host_port(target: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    raw = (target or "").strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        return parsed.hostname or "", parsed.port or default_port
    raw = raw.split("/", 1)[0]
    if raw.startswith("[") and "]" in raw:
        host, _, rest = raw[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return raw, default_port


def normalize_base_url(target: str) -> Tuple[str, str, int]:
    """Returns (base_url, host, port). A scheme-less target becomes http;
    a path on a scheme-qualified target is preserved as a path prefix."""
    raw = (target or "").strip()
    if not raw:
        return "", "", DEFAULT_PORT
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else DEFAULT_PORT)
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{path}", host, port
    host, port = split_host_port(raw)
    return f"http://{host}:{port}", host, port


def _get_json(
    url: str, timeout: int, headers: Dict[str, str]
) -> Tuple[Optional[int], Any, Optional[str]]:
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException as exc:
        return None, None, str(exc)
    status = resp.status_code
    try:
        data = resp.json()
    except ValueError:
        data = None
    return status, data, None


def _fingerprint_jupyter(
    base: str, timeout: int, headers: Dict[str, str], result: RawJupyterResult
) -> bool:
    status, data, error = _get_json(f"{base}/api", timeout, headers)
    result.endpoints.append({"path": "/api", "status": status, "error": error})
    if error is not None:
        result.error = error
        return False
    if status == 200 and isinstance(data, dict) and "version" in data:
        result.service = "jupyter"
        result.connected = True
        result.version = str(data.get("version") or "")
    elif status in (401, 403):
        result.service = "jupyter"
        result.auth_required = True
        result.status = "auth_required"
        return True
    else:
        return False

    kernels_status, kernels, kernels_error = _get_json(f"{base}/api/kernels", timeout, headers)
    result.endpoints.append({"path": "/api/kernels", "status": kernels_status, "error": kernels_error})
    if kernels_error is not None:
        result.error = kernels_error
        return True
    if kernels_status == 200 and isinstance(kernels, list):
        result.vulnerable = True
        result.status = "vulnerable"
        result.kernels_listed = len(kernels)
    elif kernels_status in (401, 403):
        result.auth_required = True
        result.status = "auth_required"
    else:
        result.status = "unexpected_response"
    return True


def _fingerprint_jupyterhub(
    base: str, timeout: int, headers: Dict[str, str], result: RawJupyterResult
) -> bool:
    status, data, error = _get_json(f"{base}/hub/api", timeout, headers)
    result.endpoints.append({"path": "/hub/api", "status": status, "error": error})
    if error is not None:
        result.error = error
        return False
    if status == 200 and isinstance(data, dict) and "version" in data:
        result.service = "jupyterhub"
        result.connected = True
        result.version = str(data.get("version") or "")
    elif status in (401, 403):
        result.service = "jupyterhub"
        result.auth_required = True
        result.status = "auth_required"
        return True
    else:
        return False

    users_status, users, users_error = _get_json(f"{base}/hub/api/users", timeout, headers)
    result.endpoints.append({"path": "/hub/api/users", "status": users_status, "error": users_error})
    if users_error is not None:
        result.error = users_error
        return True
    if users_status == 200 and isinstance(users, list):
        result.vulnerable = True
        result.status = "vulnerable"
        result.users_listed = len(users)
    elif users_status in (401, 403):
        result.auth_required = True
        result.status = "auth_required"
    else:
        result.status = "unexpected_response"
    return True


def execute(target: str, timeout: int = 10) -> RawJupyterResult:
    base, host, port = normalize_base_url(target)
    result = RawJupyterResult(target=target, host=host, port=port, base_url=base)
    if not base or not host:
        result.error = "empty target"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    headers = {"User-Agent": USER_AGENT}
    if _fingerprint_jupyter(base, timeout, headers, result):
        return result
    if _fingerprint_jupyterhub(base, timeout, headers, result):
        return result

    result.status = "not_jupyter"
    if result.error is None:
        result.error = "neither /api nor /hub/api matched a Jupyter/JupyterHub fingerprint"
    return result
