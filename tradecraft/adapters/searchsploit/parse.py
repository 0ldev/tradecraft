"""
Pure parsing functions for searchsploit output.
No subprocess or I/O logic here.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_searchsploit_output(
    stdout: str,
    query: str = "",
    cve: str = "",
    edb_id: str = "",
    file_content: str = "",
    file_path: str = "",
) -> Dict[str, Any]:
    """Parses searchsploit JSON results or examine output into a structured dict."""
    # Examine mode
    if edb_id.strip():
        title_m = re.search(r"Exploit:\s*([^\r\n]+)", stdout)
        url_m = re.search(r"URL:\s*([^\r\n]+)", stdout)
        codes_m = re.search(r"Codes:\s*([^\r\n]+)", stdout)
        verified_m = re.search(r"Verified:\s*([^\r\n]+)", stdout)

        return {
            "mode": "examine",
            "edb_id": edb_id.strip(),
            "title": title_m.group(1).strip() if title_m else "",
            "url": url_m.group(1).strip() if url_m else f"https://www.exploit-db.com/exploits/{edb_id.strip()}",
            "codes": codes_m.group(1).strip() if codes_m else "",
            "verified": verified_m.group(1).strip().lower() == "true" if verified_m else False,
            "path": file_path,
            "poc_content": file_content,
        }

    # Search mode (JSON output)
    if not stdout or not stdout.strip():
        return {
            "mode": "search",
            "query": query or cve,
            "total_exploits": 0,
            "exploits": [],
        }

    try:
        data = json.loads(stdout)
    except Exception:
        # Fallback if mixed text or JSON decode error
        json_match = re.search(r"\{.*\}", stdout, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
            except Exception:
                data = {}
        else:
            data = {}

    raw_exploits = data.get("RESULTS_EXPLOIT", [])
    exploits: List[Dict[str, Any]] = []

    for item in raw_exploits:
        if not isinstance(item, dict):
            continue
        title = item.get("Title", "")
        eid = str(item.get("EDB-ID", "")).strip()
        if not eid and not title:
            continue
        exploits.append({
            "edb_id": eid,
            "title": title,
            "date": item.get("Date_Published", ""),
            "author": item.get("Author", ""),
            "type": item.get("Type", ""),
            "platform": item.get("Platform", ""),
            "port": item.get("Port", ""),
            "verified": item.get("Verified") == "1",
            "codes": item.get("Codes", ""),
            "path": item.get("Path", ""),
        })

    return {
        "mode": "search",
        "query": query or cve,
        "total_exploits": len(exploits),
        "exploits": exploits,
    }
