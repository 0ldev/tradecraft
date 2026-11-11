"""
Raw execution: builds the dnsx argv and runs it against one or more targets.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawDnsxResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def normalize_targets(target: str) -> List[str]:
    """Parse and normalize domain/host targets, handling URLs, ports, or comma-separated lists."""
    if not target:
        return []

    raw_items = [item.strip() for item in target.split(",") if item.strip()]
    cleaned: List[str] = []

    for item in raw_items:
        # If it looks like a URL, parse host
        if "://" in item:
            parsed = urllib.parse.urlsplit(item)
            host = parsed.hostname or parsed.netloc.split(":")[0]
        else:
            host = item.split("/")[0].split(":")[0].strip()

        # Sanitize to valid domain/hostname characters
        host = re.sub(r"[^a-zA-Z0-9.\-_]", "", host).strip(".-")
        if host and host not in cleaned:
            cleaned.append(host)

    return cleaned


def build_argv(hosts_file: str, query_type: str = "recon") -> List[str]:
    cmd = [
        "dnsx",
        "-l", hosts_file,
        "-silent",
        "-j",
        "-omit-raw",
        "-cdn",
        "-asn",
    ]

    qt = (query_type or "recon").lower().strip()
    valid_single_types = {"a", "aaaa", "cname", "mx", "txt", "ns", "soa", "srv", "ptr", "caa"}

    if qt in ("recon", "all"):
        cmd.append("-recon")
    elif qt in valid_single_types:
        cmd.append(f"-{qt}")
    else:
        cmd.append("-recon")

    return cmd


def execute(target: str, query_type: str = "recon", timeout: int = 30) -> RawDnsxResult:
    hosts = normalize_targets(target)
    if not hosts:
        return RawDnsxResult(error="Missing or invalid DNS target(s)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts) + "\n")
        tmp_name = tmp.name

    try:
        cmd = build_argv(hosts_file=tmp_name, query_type=query_type)
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawDnsxResult(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
        )
    except FileNotFoundError:
        return RawDnsxResult(error="dnsx executable not found")
    except subprocess.TimeoutExpired:
        return RawDnsxResult(error=f"dnsx timed out after {timeout}s")
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass
