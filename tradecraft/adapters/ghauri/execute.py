"""
Execution logic for ghauri: advanced, low-noise SQL injection detection
and verification engine.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_TIMEOUT_SECONDS = 60


@dataclass
class RawGhauriResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    parameter: str = ""
    error: Optional[str] = None


def find_binary() -> Optional[str]:
    """Finds ghauri binary on PATH."""
    return shutil.which("ghauri")


def build_argv(
    target_url: str,
    parameter: str = "",
    data: str = "",
    headers: str = "",
    level: int = 1,
    batch: bool = True,
    binary: str = "ghauri",
) -> List[str]:
    """Builds the ghauri command-line invocation."""
    cmd = [binary, "-u", target_url.strip()]
    if parameter.strip():
        cmd.extend(["-p", parameter.strip()])
    if data.strip():
        cmd.extend(["--data", data.strip()])
    if headers.strip():
        cmd.extend(["--headers", headers.strip()])

    cmd.extend(["--level", str(max(1, min(level, 3)))])
    if batch:
        cmd.append("--batch")

    # Fast verification: check DB banner/current-user without full dump
    cmd.append("--current-user")
    return cmd


def execute(
    target: str,
    parameter: str = "",
    data: str = "",
    headers: str = "",
    level: int = 1,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RawGhauriResult:
    """Executes ghauri against target URL and parameter."""
    url = target.strip()
    if not url:
        return RawGhauriResult(error="empty target URL")

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    binary = find_binary()
    if not binary:
        return RawGhauriResult(
            target_url=url,
            parameter=parameter,
            error="ghauri executable not found on PATH",
        )

    argv = build_argv(
        target_url=url,
        parameter=parameter,
        data=data,
        headers=headers,
        level=level,
        batch=True,
        binary=binary,
    )

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawGhauriResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target_url=url,
            parameter=parameter,
        )
    except FileNotFoundError:
        return RawGhauriResult(target_url=url, parameter=parameter, error="ghauri executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawGhauriResult(target_url=url, parameter=parameter, error=f"ghauri timed out after {timeout}s")
    except Exception as exc:
        return RawGhauriResult(target_url=url, parameter=parameter, error=f"ghauri execution failed: {exc}")
