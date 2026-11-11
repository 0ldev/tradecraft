from __future__ import annotations

import shutil
from typing import Any, Dict, List, Tuple

import tradecraft.adapters.cmseek.execute as cmseek_execute
import tradecraft.adapters.cmseek.parse as cmseek_parse
from tradecraft.tools.base import Tool


class CMSeeK(Tool):
    tool_id = "cmseek"

    def is_available(self) -> bool:
        return shutil.which("python3") is not None and cmseek_execute.find_script() is not None

    def run(
        self,
        target: str,
        follow_redirect: bool = True,
        light_scan: bool = False,
        only_cms: bool = False,
    ) -> Dict[str, Any]:
        raw = cmseek_execute.execute(
            target=target,
            follow_redirect=follow_redirect,
            light_scan=light_scan,
            only_cms=only_cms,
        )
        if raw.error:
            return {
                "target": target,
                "cms_detected": False,
                "cms_id": "",
                "cms_name": "",
                "cms_version": "",
                "plugins": [],
                "themes": [],
                "users": [],
                "error": raw.error,
            }

        parsed = cmseek_parse.parse_cmseek_output(raw)
        res: Dict[str, Any] = {
            "target": target,
            "cms_detected": parsed["cms_detected"],
            "cms_id": parsed["cms_id"],
            "cms_name": parsed["cms_name"],
            "cms_version": parsed["cms_version"],
            "cms_url": parsed["cms_url"],
            "detection_method": parsed["detection_method"],
            "user_registration": parsed["user_registration"],
            "plugins": parsed["plugins"][:30],
            "themes": parsed["themes"][:30],
            "users": parsed["users"][:30],
        }

        if len(parsed["plugins"]) > 30:
            res["omitted_plugins"] = len(parsed["plugins"]) - 30
        if len(parsed["users"]) > 30:
            res["omitted_users"] = len(parsed["users"]) - 30

        if raw.stdout or raw.json_data:
            res["_full_evidence"] = {
                "target": target,
                "raw_stdout": raw.stdout,
                "json_data": raw.json_data,
                "all_plugins": parsed["plugins"],
                "all_themes": parsed["themes"],
                "all_users": parsed["users"],
            }

        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = cmseek_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("cms_detected"):
            return []

        host, port = cmseek_parse.host_port_from_target(target)
        cms_id = result.get("cms_id")
        cms_name = result.get("cms_name")
        cms_version = result.get("cms_version")

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "cms_detected": True,
            "cms_name": cms_name or cms_id,
        }
        if cms_id:
            fact["cms_id"] = cms_id
        if cms_version:
            fact["cms_version"] = cms_version

        users = result.get("users", [])
        if users:
            fact["harvested_usernames"] = users[:10]

        return [fact]
