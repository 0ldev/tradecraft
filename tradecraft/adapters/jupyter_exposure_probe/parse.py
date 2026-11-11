"""
Pure parsing for jupyter_exposure_probe. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.jupyter_exposure_probe.execute import RawJupyterResult


def parse(raw: RawJupyterResult) -> Dict[str, Any]:
    if raw.error and not raw.connected:
        return {
            "target": raw.target,
            "host": raw.host,
            "port": raw.port,
            "base_url": raw.base_url,
            "connected": False,
            "vulnerable": False,
            "status": raw.status,
            "error": raw.error,
            "endpoints": raw.endpoints,
        }

    summary = (
        f"Unauthenticated {raw.service or 'Jupyter'} API access on {raw.host}:{raw.port}"
        if raw.vulnerable
        else (
            f"{raw.service or 'Jupyter'} detected on {raw.host}:{raw.port} but its API requires authentication"
            if raw.auth_required
            else f"No unauthenticated Jupyter/JupyterHub API detected on {raw.host}:{raw.port}"
        )
    )

    return {
        "target": raw.target,
        "host": raw.host,
        "port": raw.port,
        "base_url": raw.base_url,
        "service": raw.service,
        "connected": raw.connected,
        "version": raw.version,
        "auth_required": raw.auth_required,
        "vulnerable": raw.vulnerable,
        "status": raw.status,
        "kernels_listed": raw.kernels_listed,
        "users_listed": raw.users_listed,
        "endpoints": raw.endpoints,
        "summary": summary,
        "error": raw.error,
    }
