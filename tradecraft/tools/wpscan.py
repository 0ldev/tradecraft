from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.wpscan import execute as wpscan_execute
from tradecraft.adapters.wpscan import parse as wpscan_parse
from tradecraft.tools.base import Tool


class WPScan(Tool):
    tool_id = "wpscan"

    def run(
        self,
        target: str,
        enumerate: str = "u",
        detection_mode: str = "passive",
        api_token: str = "",
        disable_tls_checks: bool = True,
    ) -> Dict[str, Any]:
        raw = wpscan_execute.execute(
            target=target,
            enumerate=enumerate,
            detection_mode=detection_mode,
            api_token=api_token,
            disable_tls_checks=disable_tls_checks,
        )
        if raw.error:
            return {
                "target": target,
                "target_url": raw.target_url,
                "is_wordpress": False,
                "plugins": [],
                "vulnerabilities": [],
                "total_vulnerabilities": 0,
                "error": raw.error,
            }

        parsed = wpscan_parse.parse_wpscan_output(raw.stdout)

        lookup_performed = wpscan_execute.has_vulnerability_api_token(api_token)
        res: Dict[str, Any] = {
            "target": target,
            "target_url": raw.target_url,
            "is_wordpress": parsed["is_wordpress"],
            "version": parsed["version"],
            "theme": parsed["theme"],
            "users": parsed["users"],
            "total_plugins": parsed["total_plugins"],
            "total_vulnerabilities": parsed["total_vulnerabilities"],
            "interesting_findings": parsed["interesting_findings"],
        }
        # total_vulnerabilities=0 looks identical whether wpscan actually
        # checked plugin/theme CVEs and found none, or never checked at all
        # (vp/vt enumeration is silently dropped without an API token --
        # see build_argv). Say which one happened so "0 vulnerabilities"
        # isn't read as a confirmed-clean result when lookup never ran.
        res["vulnerability_lookup"] = (
            "performed" if lookup_performed
            else "skipped: no WPSCAN_API_TOKEN configured -- total_vulnerabilities does not reflect a real check"
        )

        plugins = parsed["plugins"]
        if len(plugins) > 10:
            res["plugins"] = plugins[:10]
            res["omitted_plugins"] = len(plugins) - 10
            res["note"] = (
                f"{len(plugins) - 10} more plugins omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["plugins"] = plugins

        vulns = parsed["vulnerabilities"]
        if len(vulns) > 10:
            res["vulnerabilities"] = vulns[:10]
            res["omitted_vulnerabilities"] = len(vulns) - 10
        else:
            res["vulnerabilities"] = vulns

        res["_full_evidence"] = {
            "target": target,
            "target_url": raw.target_url,
            "is_wordpress": parsed["is_wordpress"],
            "version": parsed["version"],
            "theme": parsed["theme"],
            "users": parsed["users"],
            "plugins": plugins,
            "vulnerabilities": vulns,
            "interesting_findings": parsed["interesting_findings"],
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = wpscan_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = wpscan_parse.host_port_from_target(target)
        is_wp = result.get("is_wordpress", False)
        ver_info = result.get("version")
        wp_ver = ver_info.get("number") if isinstance(ver_info, dict) else None
        total_plugins = result.get("total_plugins", 0)
        total_vulns = result.get("total_vulnerabilities", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        if is_wp:
            fact["is_wordpress"] = True
        if wp_ver:
            fact["wordpress_version"] = wp_ver
        if total_plugins > 0:
            fact["wordpress_plugins"] = total_plugins
        if total_vulns > 0:
            fact["wordpress_vulnerabilities"] = total_vulns
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
