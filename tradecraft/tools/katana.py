from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.katana import execute as katana_execute
from tradecraft.adapters.katana import parse as katana_parse
from tradecraft.tools.base import Tool


class Katana(Tool):
    tool_id = "katana"

    def run(
        self,
        target: str,
        depth: int = 2,
        js_crawl: bool = True,
        crawl_duration: int = 15,
        headless: bool = False,
    ) -> Dict[str, Any]:
        raw = katana_execute.execute(
            target=target,
            depth=depth,
            js_crawl=js_crawl,
            crawl_duration=crawl_duration,
            headless=headless,
        )
        if raw.error:
            return {
                "target": target,
                "endpoints": [],
                "parameters": [],
                "error": raw.error,
            }

        parsed = katana_parse.parse_katana_output(raw.stdout)
        endpoints = parsed.get("endpoints", [])
        parameters = parsed.get("parameters", [])

        res: Dict[str, Any] = {
            "target": target,
            "total_endpoints": len(endpoints),
            "total_parameters": len(parameters),
        }

        if len(endpoints) > 15:
            res["endpoints"] = endpoints[:15]
            res["omitted_endpoints"] = len(endpoints) - 15
            res["note"] = (
                f"{len(endpoints) - 15} more endpoints omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["endpoints"] = endpoints

        if len(parameters) > 20:
            res["parameters"] = parameters[:20]
            res["omitted_parameters"] = len(parameters) - 20
        else:
            res["parameters"] = parameters

        res["_full_evidence"] = {
            "target": target,
            "total_endpoints": len(endpoints),
            "total_parameters": len(parameters),
            "endpoints": endpoints,
            "parameters": parameters,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = katana_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = katana_parse.host_port_from_target(target)
        total_endpoints = result.get("total_endpoints", len(result.get("endpoints", [])))
        total_params = result.get("total_parameters", len(result.get("parameters", [])))

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total_endpoints > 0:
            fact["endpoints_crawled"] = total_endpoints
        if total_params > 0:
            fact["params_discovered"] = total_params
            raw_params = result.get("parameters") or []
            if raw_params:
                sample = sorted({str(p) for p in raw_params})[:10]
                fact["params_sample"] = ",".join(sample)
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
