"""
Pure parsing: nmap XML output (`-oX -`) -> per-port NSE script results.
No subprocess, no I/O -- testable with plain strings.

Each port in the output carries zero or more <script id="..." output="...">
children. Attribute values come back unescaped from ElementTree, so an
output containing '&' or '<' arrives as the original characters.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List

# Per-script output is capped so one verbose `safe` script can't flood the
# model's context. Truncation is flagged on the script entry itself.
MAX_SCRIPT_OUTPUT_CHARS = 2000


def parse_script_results(xml_stdout: str) -> List[Dict[str, Any]]:
    """Returns one dict per port that reports state open, with its scripts:
      {"port": 445, "protocol": "tcp", "state": "open",
       "service": "microsoft-ds"?,
       "scripts": [{"id": "...", "output": "..."}, ...]}
    Ports with no scripts still appear (with an empty "scripts" list).
    Raises xml.etree.ElementTree.ParseError on malformed XML; the caller
    decides how to report that."""
    root = ET.fromstring(xml_stdout)
    ports: List[Dict[str, Any]] = []
    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        state = state_el.get("state") if state_el is not None else None
        if state != "open":
            continue
        entry: Dict[str, Any] = {
            "port": int(port_el.get("portid", "0")),
            "protocol": port_el.get("protocol", ""),
            "state": state,
            "scripts": [],
        }
        service_el = port_el.find("service")
        if service_el is not None and service_el.get("name"):
            entry["service"] = service_el.get("name")
        for script_el in port_el.findall("script"):
            output = script_el.get("output", "") or ""
            script: Dict[str, Any] = {"id": script_el.get("id", ""), "output": output}
            if len(output) > MAX_SCRIPT_OUTPUT_CHARS:
                script["output"] = output[:MAX_SCRIPT_OUTPUT_CHARS]
                script["output_truncated"] = True
            entry["scripts"].append(script)
        ports.append(entry)
    return ports
