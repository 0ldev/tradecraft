"""Pure parsing for dangling_resource_probe: RawDanglingResult -> model-facing dict."""
from __future__ import annotations


def parse(raw) -> dict:
    if raw.error:
        return {"target": raw.target, "host": raw.host, "error": raw.error}
    return {
        "target": raw.target,
        "host": raw.host,
        "status_code": raw.status_code,
        "dangling": raw.matched_provider is not None,
        "matched_provider": raw.matched_provider,
        "matched_signature": raw.matched_signature,
        "error": None,
    }
