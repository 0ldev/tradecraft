from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict

from tradecraft.adapters.nmap_vuln_scan import execute as nvs_execute
from tradecraft.adapters.nmap_vuln_scan import parse as nvs_parse
from tradecraft.tools.base import Tool

# parse.py's own per-script cap (MAX_SCRIPT_OUTPUT_CHARS) bounds one script's
# output, but a 20-port call where every port matches many safe/vuln scripts
# can still return hundreds of script entries in one result. Cap the total
# number of script entries returned across the whole call, same shape as
# gau's omitted_urls/note convention, rather than letting per-script bounding
# alone stand in for an aggregate one.
MAX_TOTAL_SCRIPTS = 50


class NmapVulnScan(Tool):
    tool_id = "nmap_vuln_scan"

    def run(self, target: str, ports: str) -> Dict[str, Any]:
        raw = nvs_execute.execute(target, ports)
        if raw.error:
            return {"target": target, "ports": [], "error": raw.error}
        try:
            parsed = nvs_parse.parse_script_results(raw.stdout)
        except ET.ParseError as exc:
            return {"target": target, "ports": [], "error": f"nmap XML output could not be parsed: {exc}"}

        total_scripts = sum(len(p["scripts"]) for p in parsed)
        if total_scripts <= MAX_TOTAL_SCRIPTS:
            return {"target": target, "ports": parsed}

        remaining = MAX_TOTAL_SCRIPTS
        capped_ports = []
        for p in parsed:
            scripts = p["scripts"]
            keep = scripts[:remaining] if remaining > 0 else []
            remaining = max(0, remaining - len(keep))
            capped_ports.append({**p, "scripts": keep})

        return {
            "target": target,
            "ports": capped_ports,
            "total_scripts_found": total_scripts,
            "scripts_returned": MAX_TOTAL_SCRIPTS,
            "truncated": True,
            "note": (
                f"{total_scripts - MAX_TOTAL_SCRIPTS} more NSE script results "
                "omitted to conserve context."
            ),
        }
