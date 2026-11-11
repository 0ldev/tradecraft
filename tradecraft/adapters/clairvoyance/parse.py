"""
Parsing Clairvoyance JSON output into structured GraphQL schema facts.
Pure functions, no I/O.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def parse_schema(raw_json: Optional[str]) -> Dict[str, Any]:
    """Parse recovered GraphQL schema JSON into lists of queries and mutations."""
    if not raw_json or not raw_json.strip():
        return {
            "schema_recovered": False,
            "queries": [],
            "mutations": [],
        }

    try:
        schema = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError):
        return {
            "schema_recovered": True,
            "queries": [],
            "mutations": [],
            "note": "schema recovered but in an unexpected shape -- see evidence",
        }

    if not isinstance(schema, dict):
        return {
            "schema_recovered": True,
            "queries": [],
            "mutations": [],
            "note": "schema recovered but in an unexpected shape -- see evidence",
        }

    queries: List[str] = []
    mutations: List[str] = []

    # 1. Check direct queryType / mutationType format
    if "queryType" in schema or "mutationType" in schema:
        q_fields = (schema.get("queryType") or {}).get("fields", [])
        if isinstance(q_fields, list):
            queries = [f.get("name") for f in q_fields if isinstance(f, dict) and f.get("name")]
        m_fields = (schema.get("mutationType") or {}).get("fields", [])
        if isinstance(m_fields, list):
            mutations = [f.get("name") for f in m_fields if isinstance(f, dict) and f.get("name")]

    # 2. Check data.__schema format (clairvoyance v2.x JSON output)
    __schema = schema.get("data", {}).get("__schema") if isinstance(schema.get("data"), dict) else None
    if __schema and isinstance(__schema, dict):
        q_name = (
            (__schema.get("queryType") or {}).get("name")
            if isinstance(__schema.get("queryType"), dict)
            else "Query"
        )
        m_name = (
            (__schema.get("mutationType") or {}).get("name")
            if isinstance(__schema.get("mutationType"), dict)
            else "Mutation"
        )

        types = __schema.get("types", [])
        if isinstance(types, list):
            for t in types:
                if not isinstance(t, dict):
                    continue
                t_name = t.get("name")
                if t_name == q_name and not queries:
                    fields = t.get("fields", [])
                    if isinstance(fields, list):
                        queries = [f.get("name") for f in fields if isinstance(f, dict) and f.get("name")]
                elif t_name == m_name and not mutations:
                    fields = t.get("fields", [])
                    if isinstance(fields, list):
                        mutations = [f.get("name") for f in fields if isinstance(f, dict) and f.get("name")]

    res: Dict[str, Any] = {
        "schema_recovered": True,
        "queries": queries,
        "mutations": mutations,
    }
    if not queries and not mutations:
        res["note"] = "schema recovered but in an unexpected shape -- see evidence"
    return res
