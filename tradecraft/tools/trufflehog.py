from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.trufflehog import execute as trufflehog_execute
from tradecraft.adapters.trufflehog import parse as trufflehog_parse
from tradecraft.tools.base import Tool


class TruffleHog(Tool):
    tool_id = "trufflehog"

    def run(
        self,
        target: str,
        urls: str = "",
        verify: bool = False,
        scan_git_history: bool = False,
    ) -> Dict[str, Any]:
        raw = trufflehog_execute.execute(
            target=target,
            urls=urls,
            verify=verify,
            scan_git_history=scan_git_history,
        )
        if raw.error:
            return {
                "target": target,
                "urls_scanned": raw.scanned_urls,
                "secrets": [],
                "total_secrets": 0,
                "verified_count": 0,
                "error": raw.error,
            }

        parsed = trufflehog_parse.parse_trufflehog_output(raw.stdout)

        res: Dict[str, Any] = {
            "target": target,
            "urls_scanned": raw.scanned_urls,
            "total_secrets": parsed["total_secrets"],
            "verified_count": parsed["verified_count"],
            "unverified_count": parsed["unverified_count"],
            "by_detector": parsed["by_detector"],
        }

        # A leaked ASP.NET machineKey is directly actionable (feed
        # straight into deserialization_probe_dotnet's own
        # validation_key/decryption_key/validation_algorithm/
        # decryption_algorithm parameters) -- surfaced here unmasked,
        # same "don't hide an actionable credential behind generic
        # masking" precedent auth_bootstrap's session_token and
        # jwt_analyze's forged_token already follow. This is in
        # addition to the normal masked entry each field also gets in
        # the `secrets` list below, not instead of it.
        if parsed.get("aspnet_machinekey"):
            res["aspnet_machinekey"] = parsed["aspnet_machinekey"]

        # Model-facing secrets view (with masked raw token)
        model_secrets = []
        for s in parsed["secrets"]:
            model_secrets.append({
                "detector": s["detector"],
                "description": s["description"],
                "file": s["file"],
                "line": s["line"],
                "verified": s["verified"],
                "secret": s["masked_secret"],
            })

        if len(model_secrets) > 10:
            res["secrets"] = model_secrets[:10]
            res["omitted_secrets"] = len(model_secrets) - 10
            res["note"] = (
                f"{len(model_secrets) - 10} more secrets omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["secrets"] = model_secrets

        # Full evidence holds raw secrets and full details
        res["_full_evidence"] = {
            "target": target,
            "urls_scanned": raw.scanned_urls,
            "verify": verify,
            "total_secrets": parsed["total_secrets"],
            "verified_count": parsed["verified_count"],
            "unverified_count": parsed["unverified_count"],
            "by_detector": parsed["by_detector"],
            "secrets": parsed["secrets"],
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = trufflehog_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = trufflehog_parse.host_port_from_target(target)
        total_secrets = result.get("total_secrets", len(result.get("secrets", [])))
        verified = result.get("verified_count", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total_secrets > 0:
            fact["secrets_detected"] = total_secrets
        if verified > 0:
            fact["secrets_verified"] = verified
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
