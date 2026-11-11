from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.dnsx import execute as dnsx_execute
from tradecraft.adapters.dnsx import parse as dnsx_parse
from tradecraft.tools.base import Tool


class Dnsx(Tool):
    tool_id = "dnsx"

    def run(self, target: str, query_type: str = "recon") -> Dict[str, Any]:
        raw = dnsx_execute.execute(target=target, query_type=query_type)
        if raw.error:
            return {"target": target, "records": [], "error": raw.error}

        records = dnsx_parse.parse_dns_records(raw.stdout)
        res: Dict[str, Any] = {
            "target": target,
            "total_records": len(records),
        }

        if len(records) > 10:
            res["records"] = records[:10]
            res["omitted_records"] = len(records) - 10
            res["note"] = (
                f"{len(records) - 10} more records omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["records"] = records

        res["_full_evidence"] = {
            "target": target,
            "total_records": len(records),
            "records": records,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        target = params.get("target", "")
        # Peek, don't pop: extract_facts (called after this, per
        # tradecraft/execution/loop.py) still needs the untruncated record set
        # here to produce a fact for every resolved host, not just the
        # first 10 kept in result["records"] for display. The loop strips
        # this key from `result` itself once both extractions are done, so
        # it never reaches the model.
        full = result.get("_full_evidence")
        if not target or full is None:
            return None
        # Derive canonical primary target (e.g. first hostname if comma-separated)
        hosts = dnsx_execute.normalize_targets(target)
        canonical_target = hosts[0] if hosts else target
        return canonical_target, full, hosts[1:]

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Prefer the untruncated batch (still present pre-loop-cleanup, see
        # extract_evidence above) so every resolved host gets a fact row,
        # not just the subset kept in result["records"] for the
        # model-facing display truncation.
        full_evidence = result.get("_full_evidence")
        records = full_evidence["records"] if full_evidence else result.get("records", [])
        facts: List[Dict[str, Any]] = []

        for rec in records:
            host = rec.get("host")
            if not host or not rec.get("resolves"):
                continue

            fact: Dict[str, Any] = {"host": host, "port": 53}
            if rec.get("a"):
                fact["dns_a"] = ",".join(rec["a"][:2])
            if rec.get("mx"):
                fact["dns_mx"] = ",".join(rec["mx"][:2])
            if rec.get("cname"):
                fact["dns_cname"] = ",".join(rec["cname"][:1])
            if result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]

            if len(fact) > 2:
                facts.append(fact)

        return facts
