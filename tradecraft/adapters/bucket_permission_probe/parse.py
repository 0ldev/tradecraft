"""
Pure parsing for bucket_permission_probe: turns the raw per-candidate checks
into the dict the model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.bucket_permission_probe.execute import RawBucketPermissionResult

AZURE_LIMITATION = (
    "could not distinguish private from blob-level public access (readable only "
    "by a known object key) without a known key"
)


def parse_bucket_permission_result(raw: RawBucketPermissionResult) -> Dict[str, Any]:
    if raw.error:
        return {"provider": raw.provider, "error": raw.error}

    checks = raw.checks
    summary = {
        "total": len(checks),
        "exist": sum(1 for c in checks if c.exists is True),
        "public": sum(1 for c in checks if c.publicly_listable is True),
        "errored": sum(1 for c in checks if c.error),
    }
    public = [c for c in checks if c.publicly_listable]

    if not public:
        result: Dict[str, Any] = {
            "provider": raw.provider,
            "reason": "no candidate is publicly listable",
            "all_checks_summary": summary,
        }
    else:
        result = {
            "provider": raw.provider,
            "public_buckets": [
                {
                    "candidate": c.candidate,
                    **({"container": c.container} if c.container is not None else {}),
                    "status": c.status,
                }
                for c in public
            ],
            "all_checks_summary": summary,
        }
        if raw.provider == "azure":
            result["azure_limitation"] = AZURE_LIMITATION

    if raw.truncated:
        result["truncated"] = True
    return result
