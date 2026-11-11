"""
Pure parsing functions for dalfox output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _extract_finding_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    f_type = str(item.get("type", "")).strip().upper()
    severity = str(item.get("severity", "")).strip()
    param = str(item.get("param", "")).strip()
    payload = str(item.get("payload", "")).strip()
    evidence = str(item.get("evidence", "") or item.get("message_str", "") or item.get("description", "")).strip()
    poc = str(item.get("data", "")).strip()
    method = str(item.get("method", "GET")).strip().upper()
    inject_type = str(item.get("inject_type", "")).strip()
    cwe = str(item.get("cwe", "CWE-79")).strip()
    type_desc = str(item.get("type_description", "")).strip()
    confidence = str(item.get("confidence", "")).strip()

    return {
        "type": f_type,
        "type_description": type_desc,
        "param": param,
        "severity": severity,
        "payload": payload,
        "cwe": cwe,
        "evidence": evidence,
        "poc": poc,
        "method": method,
        "inject_type": inject_type,
        "confidence": confidence,
    }


def parse_dalfox_output(
    json_content: str = "",
    stdout: str = "",
) -> Dict[str, Any]:
    """
    Parses dalfox findings from JSON report file or stdout fallback.
    """
    raw_findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {}

    # 1. Parse JSON file content if available
    if json_content and json_content.strip():
        try:
            data = json.loads(json_content.strip())
            if isinstance(data, dict):
                items = data.get("findings", [])
                if isinstance(items, list):
                    raw_findings.extend(items)
                meta = data.get("meta", {})
            elif isinstance(data, list):
                raw_findings.extend(data)
        except json.JSONDecodeError:
            # Try line-by-line JSON parse
            for line in json_content.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        if "findings" in obj and isinstance(obj["findings"], list):
                            raw_findings.extend(obj["findings"])
                            meta.update(obj.get("meta", {}))
                        elif "type" in obj or "param" in obj or "payload" in obj:
                            raw_findings.append(obj)
                except json.JSONDecodeError:
                    continue

    # 2. Fallback to parsing stdout if no findings extracted
    if not raw_findings and stdout and stdout.strip():
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    if "findings" in obj and isinstance(obj["findings"], list):
                        raw_findings.extend(obj["findings"])
                        meta.update(obj.get("meta", {}))
                    elif "type" in obj or "param" in obj or "payload" in obj:
                        raw_findings.append(obj)
            except json.JSONDecodeError:
                continue

    findings: List[Dict[str, Any]] = []
    vulnerable_count = 0
    reflected_count = 0
    dom_count = 0

    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        entry = _extract_finding_dict(item)
        findings.append(entry)

        t = entry["type"].upper()
        sev = entry["severity"].lower()
        if t == "V" or sev in ("high", "critical"):
            vulnerable_count += 1
        elif t == "R" or sev in ("reflected", "medium"):
            reflected_count += 1
        elif t == "A" or "dom" in sev:
            dom_count += 1

    return {
        "findings": findings,
        "total_findings": len(findings),
        "vulnerable_count": vulnerable_count,
        "reflected_count": reflected_count,
        "dom_count": dom_count,
        "meta": meta,
    }
