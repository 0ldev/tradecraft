"""
Raw execution for docker_api_probe: up to three anonymous GETs against the
Docker Engine API v2 (no credential used or sent): /version, /info, and
/containers/json. Read-only -- never creates, starts, stops, or deletes a
container, and never pulls an image. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_PORT = 2375
MAX_CONTAINERS = 25


@dataclass
class RawDockerApiResult:
    target: str = ""
    host: str = ""
    port: int = DEFAULT_PORT
    reachable: bool = False
    version_status: Optional[int] = None
    version_info: Dict[str, Any] = field(default_factory=dict)
    info_status: Optional[int] = None
    info: Dict[str, Any] = field(default_factory=dict)
    containers_status: Optional[int] = None
    containers: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


def split_host_port(target: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    raw = (target or "").strip()
    if raw.startswith("http://"):
        raw = raw[len("http://"):]
    elif raw.startswith("https://"):
        raw = raw[len("https://"):]
    raw = raw.split("/", 1)[0]
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            return raw, default_port
    return raw, default_port


def execute(target: str, timeout: int = 10) -> RawDockerApiResult:
    host, port = split_host_port(target)
    result = RawDockerApiResult(target=target, host=host, port=port)
    if not host:
        result.error = "empty target host"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    base = f"http://{host}:{port}"
    headers = {"User-Agent": USER_AGENT}

    try:
        version_resp = requests.get(f"{base}/version", headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        result.error = f"GET /version failed: {exc}"
        return result

    result.version_status = version_resp.status_code
    if version_resp.status_code != 200:
        result.error = f"/version returned HTTP {version_resp.status_code} -- not an open Docker API"
        return result
    try:
        result.version_info = version_resp.json()
    except ValueError:
        result.error = "/version returned HTTP 200 with a non-JSON body -- not a Docker Engine API"
        return result

    result.reachable = True

    try:
        info_resp = requests.get(f"{base}/info", headers=headers, timeout=timeout)
        result.info_status = info_resp.status_code
        if info_resp.status_code == 200:
            result.info = info_resp.json()
    except (requests.RequestException, ValueError):
        pass  # /version already confirmed the finding; /info is best-effort detail

    try:
        containers_resp = requests.get(
            f"{base}/containers/json",
            params={"all": "true", "limit": MAX_CONTAINERS},
            headers=headers,
            timeout=timeout,
        )
        result.containers_status = containers_resp.status_code
        if containers_resp.status_code == 200:
            data = containers_resp.json()
            if isinstance(data, list):
                result.containers = data[:MAX_CONTAINERS]
    except (requests.RequestException, ValueError):
        pass

    return result
