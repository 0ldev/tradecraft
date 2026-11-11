from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.httpx import execute as httpx_execute
from tradecraft.adapters.httpx import parse as httpx_parse
from tradecraft.tools.base import Tool


class HttpxProbe(Tool):
    tool_id = "httpx_probe"

    def run(self, target: str, headers: Optional[str] = None) -> Dict[str, Any]:
        raw = httpx_execute.execute(target, headers=headers)
        if raw.error:
            return {"target": target, "live": False, "error": raw.error}

        hosts = httpx_execute.normalize_targets(target)
        if len(hosts) <= 1:
            probe = httpx_parse.parse_probe(raw.stdout)
            if probe is None:
                return {"target": target, "live": False}
            res: Dict[str, Any] = {"target": target, "live": True, **probe}
            raw_data = httpx_parse.parse_raw(raw.stdout)
            if raw_data:
                res["_full_evidence"] = raw_data
            return res

        results = httpx_parse.parse_probe_many(raw.stdout)
        res = {"target": target, "probed_count": len(hosts), "live_count": len(results)}
        if len(results) > 15:
            res["results"] = results[:15]
            res["omitted_results"] = len(results) - 15
            res["note"] = f"{len(results) - 15} more probed hosts omitted to conserve context. Use read_evidence to inspect all."
        else:
            res["results"] = results

        res["_full_evidence"] = {"target": target, "results": results}
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        target = params.get("target", "")
        # Peek, don't pop: extract_facts (called after this, per
        # tradecraft/execution/loop.py) still needs the untruncated batch here
        # to produce a fact for every probed host, not just the first 15
        # kept in result["results"] for display. The loop strips this key
        # from `result` itself once both extractions are done, so it never
        # reaches the model.
        full = result.get("_full_evidence")
        if not target or full is None:
            return None
        hosts = httpx_execute.normalize_targets(target)
        canonical_target = hosts[0] if hosts else target
        return canonical_target, full, hosts[1:]

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "results" in result:
            # Prefer the untruncated batch (still present pre-loop-cleanup,
            # see extract_evidence above) so every probed host gets a fact
            # row, not just the subset kept in result["results"] for the
            # model-facing display truncation.
            full_evidence = result.get("_full_evidence")
            entries = full_evidence["results"] if full_evidence else result.get("results", [])
            facts = []
            for entry in entries:
                host, port = entry.get("host"), entry.get("port")
                if not host or port is None:
                    continue
                fields: Dict[str, Any] = {}
                if entry.get("status_code") is not None:
                    fields["http_status"] = entry["status_code"]
                if entry.get("title"):
                    fields["http_title"] = entry["title"]
                if entry.get("missing_security_headers"):
                    fields["missing_security_headers"] = ", ".join(entry["missing_security_headers"])
                if entry.get("tech"):
                    fields["httpx_tech"] = ", ".join(entry["tech"])
                if result.get("evidence_id"):
                    fields["evidence"] = result["evidence_id"]
                facts.append({"host": host, "port": int(port), **fields})
            return facts

        if not result.get("live"):
            return []
        host, port = result.get("host"), result.get("port")
        if not host or port is None:
            return []
        fields: Dict[str, Any] = {}
        if result.get("status_code") is not None:
            fields["http_status"] = result["status_code"]
        if result.get("title"):
            fields["http_title"] = result["title"]
        if result.get("missing_security_headers"):
            fields["missing_security_headers"] = ", ".join(result["missing_security_headers"])
        if result.get("tech"):
            fields["httpx_tech"] = ", ".join(result["tech"])
        if result.get("evidence_id"):
            fields["evidence"] = result["evidence_id"]
        return [{"host": host, "port": int(port), **fields}]
