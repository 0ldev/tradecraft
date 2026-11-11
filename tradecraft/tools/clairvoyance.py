from __future__ import annotations

import shutil
import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.clairvoyance import execute as clairvoyance_execute
from tradecraft.adapters.clairvoyance import parse as clairvoyance_parse
from tradecraft.tools.base import Tool


class Clairvoyance(Tool):
    tool_id = "clairvoyance"

    def is_available(self) -> bool:
        return shutil.which("python3") is not None and clairvoyance_execute.find_script() is not None

    def run(self, target: str) -> Dict[str, Any]:
        raw = clairvoyance_execute.execute(target)
        if raw.error:
            return {
                "target": target,
                "schema_recovered": False,
                "queries": [],
                "mutations": [],
                "error": raw.error,
            }

        parsed = clairvoyance_parse.parse_schema(raw.json_output)
        res = {
            "target": target,
            **parsed,
        }
        res["_full_evidence"] = {
            "target": target,
            "raw_schema": raw.json_output,
            "queries": parsed.get("queries", []),
            "mutations": parsed.get("mutations", []),
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("schema_recovered"):
            return []
        queries = result.get("queries", [])
        mutations = result.get("mutations", [])
        if not queries and not mutations:
            return []

        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or (80 if parsed.scheme == "http" else 443)

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "graphql_schema_recovered_without_introspection": f"{len(queries)} queries, {len(mutations)} mutations",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
