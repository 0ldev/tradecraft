"""
Raw execution for registry_tag_enum: an anonymous bearer-token fetch (Docker
Hub only) and one GET to the Docker Registry V2 tags/list endpoint. Lists tags
only -- never pulls a manifest or layer. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

DOCKER_HUB_REGISTRY = "registry-1.docker.io"
DOCKER_HUB_AUTH_URL = "https://auth.docker.io/token"


@dataclass
class RawRegistryTagResult:
    repository: str = ""
    registry: str = ""
    tags: List[str] = field(default_factory=list)
    total_tags: int = 0
    status: Optional[int] = None
    error: Optional[str] = None


def _anonymous_docker_hub_token(repository: str, timeout: int) -> Optional[str]:
    """Same anonymous pull token an unauthenticated 'docker pull' obtains.
    Any failure returns None, and the tags call is then tried without a token."""
    try:
        resp = requests.get(
            DOCKER_HUB_AUTH_URL,
            params={"service": "registry.docker.io", "scope": f"repository:{repository}:pull"},
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json().get("token")
    except ValueError:
        return None


def execute(repository: str, registry: str = "", timeout: int = 10) -> RawRegistryTagResult:
    repository = (repository or "").strip().strip("/")
    raw = RawRegistryTagResult(repository=repository)
    if not repository:
        raw.error = "no repository given"
        return raw
    if requests is None:
        raw.error = "requests library not available"
        return raw

    registry = (registry or DOCKER_HUB_REGISTRY).strip()
    raw.registry = registry

    token = None
    if registry == DOCKER_HUB_REGISTRY:
        token = _anonymous_docker_hub_token(repository, timeout)

    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(
            f"https://{registry}/v2/{repository}/tags/list",
            headers=headers,
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException as exc:
        raw.error = str(exc)
        return raw

    raw.status = resp.status_code
    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            raw.error = "HTTP 200 with a non-JSON body"
            return raw
        raw.tags = list(data.get("tags") or [])
        raw.total_tags = len(raw.tags)
    elif resp.status_code == 401:
        raw.error = "registry requires authentication this call did not provide"
    # 404 (repository not found) is a completed outcome, handled in parse.py.
    return raw
