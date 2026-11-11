"""
Pure parsing for registry_tag_enum: turns the raw tags/list result into the
dict the model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.registry_tag_enum.execute import RawRegistryTagResult

MAX_TAGS_RETURNED = 200


def parse_registry_tag_result(raw: RawRegistryTagResult) -> Dict[str, Any]:
    if raw.error:
        return {"repository": raw.repository, "registry": raw.registry, "error": raw.error}

    if not raw.tags:
        if raw.status == 404:
            reason = "repository not found on this registry"
        else:
            reason = "repository exists but has no tags, or was not found"
        return {"repository": raw.repository, "registry": raw.registry, "reason": reason}

    tags = sorted(raw.tags)
    out: Dict[str, Any] = {
        "repository": raw.repository,
        "registry": raw.registry,
        "total_tags": len(tags),
        "tags": tags[:MAX_TAGS_RETURNED],
    }
    if len(tags) > MAX_TAGS_RETURNED:
        out["truncated"] = True
    return out
