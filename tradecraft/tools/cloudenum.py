from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cloudenum import execute as cloudenum_execute
from tradecraft.adapters.cloudenum import parse as cloudenum_parse
from tradecraft.tools.base import Tool


class Cloudenum(Tool):
    tool_id = "cloudenum"

    def run(
        self,
        target: str,
        quickscan: bool = True,
        disable_aws: bool = False,
        disable_azure: bool = False,
        disable_gcp: bool = False,
        threads: int = 5,
    ) -> Dict[str, Any]:
        raw = cloudenum_execute.execute(
            target=target,
            quickscan=quickscan,
            disable_aws=disable_aws,
            disable_azure=disable_azure,
            disable_gcp=disable_gcp,
            threads=threads,
        )
        if raw.error:
            return {
                "target": target,
                "keyword": raw.keyword,
                "resources": [],
                "total_resources": 0,
                "public_count": 0,
                "error": raw.error,
            }

        parsed = cloudenum_parse.parse_cloudenum_output(
            json_content=raw.json_content,
            stdout=raw.stdout,
        )

        res: Dict[str, Any] = {
            "target": target,
            "keyword": raw.keyword,
            "total_resources": parsed["total_resources"],
            "public_count": parsed["public_count"],
            "protected_count": parsed["protected_count"],
            "disabled_count": parsed["disabled_count"],
            "by_platform": parsed["by_platform"],
        }

        resources = parsed["resources"]
        if len(resources) > 15:
            res["resources"] = resources[:15]
            res["omitted_resources"] = len(resources) - 15
            res["note"] = (
                f"{len(resources) - 15} more cloud resources omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["resources"] = resources

        res["_full_evidence"] = {
            "target": target,
            "keyword": raw.keyword,
            "quickscan": quickscan,
            "total_resources": parsed["total_resources"],
            "public_count": parsed["public_count"],
            "protected_count": parsed["protected_count"],
            "disabled_count": parsed["disabled_count"],
            "by_platform": parsed["by_platform"],
            "resources": resources,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        keyword = result.get("keyword") or full.get("keyword") or target
        return keyword, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, _ = cloudenum_parse.host_port_from_target(target)
        total_resources = result.get("total_resources", len(result.get("resources", [])))
        public_count = result.get("public_count", 0)

        # Cloud_enum searches third-party cloud provider storage (S3/Azure/
        # GCP) by keyword -- it never probes the target's own port 443.
        # Port 0 is the sentinel this codebase already uses for a fact
        # with no real port (see tradecraft/tools/interactsh.py). Reusing a
        # real port number here would risk this fact silently merging
        # into (host, 443)'s record with whatever a real HTTPS-port
        # service tool (nmap_scan, httpx_probe, ...) reports for the same
        # apex.
        fact: Dict[str, Any] = {"host": host, "port": 0}
        if total_resources > 0:
            fact["cloud_assets_found"] = total_resources
        if public_count > 0:
            fact["cloud_public_buckets"] = public_count
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
