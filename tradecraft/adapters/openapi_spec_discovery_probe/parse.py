"""
Parsing logic for openapi_spec_discovery_probe results. Pure functions,
no I/O. Returns the FULL endpoint list for each spec found -- the tool
layer caps the displayed list and offloads the rest to evidence, the
same split response_security_audit's SRI list already uses.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.openapi_spec_discovery_probe.execute import OpenApiSpecDiscoveryResult, SpecHit

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
INTEREST_KEYWORDS = ("admin", "internal", "debug", "test")


def _endpoints_for(hit: SpecHit) -> List[str]:
    endpoints: List[str] = []
    paths = hit.raw_spec.get("paths")
    if not isinstance(paths, dict):
        return endpoints
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods.keys():
            if method.lower() not in HTTP_METHODS:
                continue
            endpoints.append(f"{method.upper()} {path}")
    return endpoints


def parse(result: OpenApiSpecDiscoveryResult) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "target": result.target,
        "base_url": result.base_url,
        "checked_paths": result.checked_paths,
        "error": result.error,
        "specs_found": [],
    }

    for hit in result.hits:
        endpoints = _endpoints_for(hit)
        of_interest = [e for e in endpoints if any(kw in e.lower() for kw in INTEREST_KEYWORDS)]
        output["specs_found"].append({
            "path": hit.path,
            "title": hit.title,
            "spec_version": hit.spec_version,
            "api_version": hit.api_version,
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "of_interest": of_interest,
        })

    return output
