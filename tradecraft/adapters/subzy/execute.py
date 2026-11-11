"""
Raw execution: builds the subzy argv and runs it against one or more targets.
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
class RawSubzyResult:
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
        if "://" in item:
            parsed = urllib.parse.urlsplit(item)
            host = parsed.hostname or parsed.netloc.split(":")[0]
        else:
            host = item.split("/")[0].split(":")[0].strip()

        host = re.sub(r"[^a-zA-Z0-9.\-_]", "", host).strip(".-")
        if host and host not in cleaned:
            cleaned.append(host)

    return cleaned


def build_argv(targets_file: str, concurrency: int = 10) -> List[str]:
    return [
        "subzy",
        "run",
        "--targets", targets_file,
        "--hide_fails",
        "--concurrency", str(concurrency),
    ]


def execute(target: str, concurrency: int = 10, timeout: int = 60) -> RawSubzyResult:
    hosts = normalize_targets(target)
    if not hosts:
        return RawSubzyResult(error="Missing or invalid takeover target(s)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(hosts) + "\n")
        tmp_name = tmp.name

    try:
        cmd = build_argv(targets_file=tmp_name, concurrency=concurrency)
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawSubzyResult(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
        )
    except FileNotFoundError:
        return RawSubzyResult(error="subzy executable not found")
    except subprocess.TimeoutExpired:
        return RawSubzyResult(error=f"subzy timed out after {timeout}s")
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass
