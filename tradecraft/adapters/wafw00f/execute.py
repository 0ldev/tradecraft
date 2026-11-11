"""
Raw execution: builds the wafw00f argv and runs it, writing JSON to a
temp file (wafw00f's own CLI has no stdout JSON mode). Cleanup happens
here since parse.py stays I/O-free.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawWafScanResult:
    json_output: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def to_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    if target.rsplit(":", 1)[-1] == "443":
        return f"https://{target}"
    return f"http://{target}"


def build_argv(url: str, out_path: str) -> list[str]:
    return ["wafw00f", url, "-o", out_path, "-f", "json", "-a"]


def execute(target: str, timeout: int = 120) -> RawWafScanResult:
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        try:
            process = subprocess.run(
                build_argv(to_url(target), out_path), text=True, capture_output=True, timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return RawWafScanResult(error="wafw00f executable not found")
        except subprocess.TimeoutExpired:
            return RawWafScanResult(error=f"wafw00f timed out after {timeout}s")

        json_output = ""
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path) as f:
                json_output = f.read()
        return RawWafScanResult(json_output=json_output, stderr=process.stderr, returncode=process.returncode)
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
