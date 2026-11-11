"""
Pure parsing functions for commix command injection output.
No subprocess or I/O logic here.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_commix_output(
    stdout: str,
    logs_content: str = "",
    target_url: str = "",
    tested_param: str = "",
) -> Dict[str, Any]:
    """Parses commix stdout and optional logs.txt content into a structured dict."""
    # Prefer logs_content if available, as it contains full boundaries and curl commands
    combined = f"{logs_content}\n{stdout}".strip()
    if not combined:
        return {
            "target": target_url,
            "parameter": tested_param,
            "vulnerable": False,
            "total_injections": 0,
            "injections": [],
            "target_os": "unknown",
        }

    vulnerable = False
    injections: List[Dict[str, Any]] = []
    target_os = "unknown"

    os_match = re.search(r"Target OS:\s*([A-Za-z0-9_\-]+)", combined, re.IGNORECASE)
    if os_match:
        target_os = os_match.group(1).strip()
    elif "Target OS: Unix" in combined or "Linux" in combined:
        target_os = "Unix"
    elif "Target OS: Windows" in combined:
        target_os = "Windows"

    # 2. Parse structured injection points from logs_content or stdout
    # Commix logs.txt format:
    # Parameter: <name> (<method>)
    #  * Technique: <technique>
    #  * Type: <type>
    #  * Boundary: <boundary>
    #  * Payload: <payload>
    #  * Reproduce: <cmd>
    current_param = tested_param
    param_match = re.search(r"Parameter:\s*([A-Za-z0-9_\-]+)", combined)
    if param_match:
        current_param = param_match.group(1).strip()

    # Match each injection block
    # Splitting on "* Technique:" or finding all technique blocks
    blocks = re.findall(
        r"\*\s*Technique:\s*([^\n\r]+)[\r\n]+"
        r"\s*\*\s*Type:\s*([^\n\r]+)[\r\n]+"
        r"(?:\s*\*\s*Boundary:\s*([^\n\r]+)[\r\n]+)?"
        r"\s*\*\s*Payload:\s*([^\n\r]+)[\r\n]+"
        r"(?:\s*\*\s*Reproduce:\s*([^\n\r]+))?",
        combined,
    )

    seen_injections = set()
    for match in blocks:
        tech, inj_type, boundary, payload, reproduce = match
        key = (tech.strip(), payload.strip())
        if key in seen_injections:
            continue
        seen_injections.add(key)
        injections.append({
            "parameter": current_param,
            "technique": tech.strip(),
            "type": inj_type.strip(),
            "boundary": boundary.strip() if boundary else "",
            "payload": payload.strip(),
            "reproduce": reproduce.strip() if reproduce else "",
        })

    if injections:
        vulnerable = True

    # Check stdout text markers if no structured blocks found
    if not vulnerable:
        has_positive = any(
            marker in stdout
            for marker in ("is vulnerable", "seems to be injectable", "appears to be injectable")
        )
        has_negation = any(
            neg in stdout
            for neg in ("does not seem to be injectable", "do not appear to be injectable", "not seem to be injectable")
        )
        if has_positive and not has_negation:
            vulnerable = True
            payload_m = re.search(r"Payload:\s*([^\n\r]+)", stdout)
            payload = payload_m.group(1).strip() if payload_m else ""
            tech_m = re.search(r"via\s+([^\n\r]+?)(?:\s+technique|\s+injection|\.|$)", stdout, re.IGNORECASE)
            tech = tech_m.group(1).strip() if tech_m else "unknown"
            injections.append({
                "parameter": current_param,
                "technique": tech,
                "type": "command injection",
                "boundary": "",
                "payload": payload,
                "reproduce": "",
            })

    return {
        "target": target_url,
        "parameter": current_param or tested_param,
        "vulnerable": vulnerable,
        "total_injections": len(injections),
        "injections": injections,
        "target_os": target_os,
    }
