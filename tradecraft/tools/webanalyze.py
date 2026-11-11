from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.webanalyze import execute as webanalyze_execute
from tradecraft.adapters.webanalyze import parse as webanalyze_parse
from tradecraft.tools.base import Tool


class Webanalyze(Tool):
    tool_id = "webanalyze"

    def run(self, target: str) -> Dict[str, Any]:
        raw = webanalyze_execute.execute(target)
        if raw.error:
            return {"target": target, "technologies": [], "error": raw.error}
        if raw.returncode != 0 and not raw.stdout.strip():
            error_msg = raw.stderr.strip() or f"webanalyze exited with returncode {raw.returncode}"
            return {"target": target, "technologies": [], "error": error_msg}
        technologies = webanalyze_parse.parse_webanalyze_output(raw.stdout)
        host, port = webanalyze_parse.host_port_from_target(target)
        return {
            "target": target,
            "host": host,
            "port": port,
            "technologies": technologies,
        }

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        host = result.get("host")
        port = result.get("port")
        if not host or port is None:
            if not target:
                return []
            host, port = webanalyze_parse.host_port_from_target(target)
        techs = result.get("technologies", [])
        if not host or not techs:
            return []
        tech_names = [t["name"] for t in techs if isinstance(t, dict) and t.get("name")]
        if not tech_names:
            return []
        return [{"host": host, "port": int(port), "webanalyze_tech": ", ".join(tech_names)}]
