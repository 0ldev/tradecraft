"""
Subprocess execution for Clairvoyance. Runs Clairvoyance against a GraphQL target URL
to recover schemas when introspection is disabled.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

SCRIPT_PATH = "/opt/clairvoyance/clairvoyance.py"


@dataclass
class RawClairvoyanceResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    json_output: str = ""
    target_url: str = ""
    error: Optional[str] = None


def find_script() -> Optional[str]:
    if os.path.isfile(SCRIPT_PATH):
        return SCRIPT_PATH
    which = shutil.which("clairvoyance")
    if which:
        return which
    home_script = os.path.expanduser("~/clairvoyance/clairvoyance.py")
    if os.path.isfile(home_script):
        return home_script
    return None


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not (target.startswith("http://") or target.startswith("https://")):
        target = f"https://{target}"
    return target


def execute(target: str, timeout: int = 300) -> RawClairvoyanceResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawClairvoyanceResult(error="Empty target")

    script = find_script()
    if not script:
        return RawClairvoyanceResult(
            target_url=target_url,
            error=f"clairvoyance not found at {SCRIPT_PATH}",
        )

    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="clairvoyance_")
    os.close(out_fd)

    if script.endswith(".py"):
        cmd = ["python3", script, target_url, "-o", out_path]
    else:
        cmd = [script, target_url, "-o", out_path]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        json_out = ""
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                json_out = f.read()

        return RawClairvoyanceResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            json_output=json_out,
            target_url=target_url,
        )
    except FileNotFoundError:
        return RawClairvoyanceResult(target_url=target_url, error="python3 binary not found")
    except subprocess.TimeoutExpired:
        return RawClairvoyanceResult(target_url=target_url, error="Clairvoyance execution timed out")
    finally:
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
