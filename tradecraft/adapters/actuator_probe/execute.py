"""
Raw execution for actuator_probe: GETs a fixed list of Spring Boot Actuator
paths against a base URL and records each response's status and content type.
No parsing here -- parse.py's job.
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

ACTUATOR_PATHS = [
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/heapdump", "/actuator/mappings", "/actuator/beans",
    "/actuator/configprops", "/actuator/loggers", "/actuator/threaddump",
    "/actuator/metrics", "/actuator/httptrace", "/actuator/trace",
    "/actuator/dump",
    "/health", "/info", "/env", "/heapdump", "/mappings", "/beans",
    "/configprops", "/loggers", "/threaddump", "/metrics", "/trace",
    "/dump",
]  # 26 entries

HIGH_VALUE = {
    "env", "heapdump", "configprops", "mappings", "loggers",
    "httptrace", "trace", "dump",
}  # matched against the path's last segment


@dataclass
class PathResult:
    path: str
    status: Optional[int] = None
    content_type: str = ""
    body_length: Optional[int] = None
    looks_like_actuator: bool = False
    error: Optional[str] = None


@dataclass
class RawActuatorResult:
    target: str = ""
    results: List[PathResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Ensure target has a valid HTTP/HTTPS scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def _looks_like_actuator(status: int, content_type: str, body: bytes) -> bool:
    if status in (401, 403):
        # The framework's own security filter produced this; it confirms mounting.
        return True
    if status == 200:
        return "json" in content_type.lower() or body.lstrip()[:1] == b"{"
    return False


def execute(target: str, timeout: int = 8) -> RawActuatorResult:
    if requests is None:
        return RawActuatorResult(target=target, error="requests library not available")

    base = normalize_target_url(target).rstrip("/")
    if not base:
        return RawActuatorResult(target=target, error="empty target")

    result = RawActuatorResult(target=base)
    headers = {"User-Agent": USER_AGENT}
    for path in ACTUATOR_PATHS:
        entry = PathResult(path=path)
        try:
            resp = requests.get(
                base + path,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            entry.status = resp.status_code
            entry.content_type = resp.headers.get("Content-Type", "")
            entry.body_length = len(resp.content)
            entry.looks_like_actuator = _looks_like_actuator(
                resp.status_code, entry.content_type, resp.content
            )
        except requests.RequestException as exc:
            entry.error = str(exc)
        result.results.append(entry)

    return result
