"""
Execution logic for cero: subdomain discovery via Certificate Transparency.
"""
from __future__ import annotations

import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawCeroResult:
    domains: List[str] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target(target: str) -> str:
    """Extracts bare domain name from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        raw = parsed.hostname or raw
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            raw = parts[0]
    return raw.strip().lower()


def execute(target: str, timeout: int = 120) -> RawCeroResult:
    """Executes cero against target to extract SANs/subdomains from CT logs."""
    clean_target = normalize_target(target)
    if not clean_target:
        return RawCeroResult(domains=[], error="Invalid target domain")

    cmd = ["cero", clean_target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return RawCeroResult(domains=[], error="cero executable not found in PATH")
    except subprocess.TimeoutExpired:
        return RawCeroResult(domains=[], error="cero execution timed out")
    except Exception as exc:
        return RawCeroResult(domains=[], error=str(exc))

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return RawCeroResult(domains=lines)
