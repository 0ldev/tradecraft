"""
Pure parsing for docker_api_probe. No I/O here.
"""
from __future__ import annotations

from typing import Any, Dict


def parse(raw) -> Dict[str, Any]:
    if not raw.reachable:
        return {"target": raw.target, "host": raw.host, "port": raw.port, "reachable": False, "error": raw.error}

    container_names = []
    for c in raw.containers:
        names = c.get("Names") or []
        if names:
            first = names[0]
            container_names.append(first[1:] if first.startswith("/") else first)

    return {
        "target": raw.target,
        "host": raw.host,
        "port": raw.port,
        "reachable": True,
        "docker_version": raw.version_info.get("Version"),
        "api_version": raw.version_info.get("ApiVersion"),
        "os": raw.version_info.get("Os"),
        "arch": raw.version_info.get("Arch"),
        "kernel_version": raw.version_info.get("KernelVersion"),
        "containers_total": raw.info.get("Containers"),
        "containers_running": raw.info.get("ContainersRunning"),
        "images_total": raw.info.get("Images"),
        "server_version": raw.info.get("ServerVersion"),
        "operating_system": raw.info.get("OperatingSystem"),
        "container_names": container_names,
        "container_count_listed": len(raw.containers),
        "error": raw.error,
    }
