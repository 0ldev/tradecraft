"""
Pure parsing functions for sqlmap output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import csv
import io
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_sqlmap_output(
    csv_content: str = "",
    log_content: str = "",
    stdout: str = "",
) -> Dict[str, Any]:
    """
    Parses sqlmap results from CSV summary, target log file, and/or stdout.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    injectable = False
    dbms: Optional[str] = None
    place = ""
    param_name = ""

    # 1. Parse CSV content if available
    if csv_content and csv_content.strip():
        try:
            reader = csv.reader(io.StringIO(csv_content.strip()))
            header = None
            for row in reader:
                if not row:
                    continue
                if header is None:
                    header = [c.strip().lower() for c in row]
                    continue
                if len(row) >= 3:
                    injectable = True
                    # Target URL,Place,Parameter,Technique(s),Note(s)
                    target_url = row[0].strip() if len(row) > 0 else ""
                    p_place = row[1].strip() if len(row) > 1 else "GET"
                    p_param = row[2].strip() if len(row) > 2 else ""
                    p_tech = row[3].strip() if len(row) > 3 else ""
                    p_notes = row[4].strip() if len(row) > 4 else ""

                    vulnerabilities.append({
                        "url": target_url,
                        "place": p_place,
                        "parameter": p_param,
                        "techniques": p_tech,
                        "notes": p_notes,
                    })
        except Exception:
            pass

    # 2. Extract DBMS from stdout or log
    combined_text = f"{stdout}\n{log_content}"
    for line in combined_text.splitlines():
        line_clean = line.strip()
        # E.g. "[INFO] the back-end DBMS is MySQL"
        dbms_match = re.search(r"back-end DBMS is\s+([^,\(\n]+)", line_clean, re.IGNORECASE)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
            injectable = True

        # Check for confirmed injection indicators in stdout
        if "is vulnerable" in line_clean.lower() or "sqlmap identified the following injection points" in line_clean.lower():
            injectable = True

    # 3. Parse detailed parameter injection blocks from log or stdout
    # E.g.:
    # Parameter: id (GET)
    #     Type: boolean-based blind
    #     Title: AND boolean-based blind - WHERE or HAVING clause
    #     Payload: id=1 AND 1234=1234
    param_blocks = re.findall(
        r"Parameter:\s*([^\s\(]+)\s*\(([^\)]+)\)(.*?)(?=(?:Parameter:|\Z))",
        combined_text,
        re.DOTALL,
    )
    for p_name, p_place, p_body in param_blocks:
        injectable = True
        types = re.findall(r"Type:\s*([^\n]+)", p_body)
        titles = re.findall(r"Title:\s*([^\n]+)", p_body)
        payloads = re.findall(r"Payload:\s*([^\n]+)", p_body)

        tech_desc = ", ".join(t.strip() for t in types) if types else "unknown"
        title_desc = titles[0].strip() if titles else ""
        payload_desc = payloads[0].strip() if payloads else ""

        existing = next((v for v in vulnerabilities if v.get("parameter") == p_name.strip()), None)
        if existing:
            if not existing.get("techniques") and tech_desc:
                existing["techniques"] = tech_desc
            if title_desc:
                existing["title"] = title_desc
            if payload_desc:
                existing["payload"] = payload_desc
        else:
            vulnerabilities.append({
                "parameter": p_name.strip(),
                "place": p_place.strip(),
                "techniques": tech_desc,
                "title": title_desc,
                "payload": payload_desc,
            })

    return {
        "injectable": injectable,
        "total_vulnerabilities": len(vulnerabilities),
        "dbms": dbms,
        "vulnerabilities": vulnerabilities,
    }
