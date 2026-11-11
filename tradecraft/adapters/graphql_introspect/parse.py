"""
Parses GraphQL introspection query response.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.graphql_introspect.execute import RawGraphqlResult


def parse_introspection(raw: RawGraphqlResult) -> Dict[str, Any]:
    if raw.error:
        return {"introspection_enabled": None, "error": raw.error}
    body = raw.body or {}
    schema = (body.get("data") or {}).get("__schema")
    if schema:
        type_names = [t.get("name") for t in schema.get("types", []) if t.get("name")]
        return {
            "introspection_enabled": True,
            "query_type": (schema.get("queryType") or {}).get("name"),
            "type_count": len(type_names),
            "sample_types": type_names[:20],
        }
    return {"introspection_enabled": False, "errors": body.get("errors")}
