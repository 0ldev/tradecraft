"""
Subprocess execution for gowitness v3.
Captures a screenshot of a URL, reads the resulting image bytes, and cleans up temporary files.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class RawGowitnessResult:
    png_bytes: bytes
    final_url: str
    error: Optional[str] = None


def build_argv(target: str, screenshot_path: str, timeout: int = 20, delay: int = 1) -> List[str]:
    return [
        "gowitness",
        "scan",
        "single",
        "-u",
        target,
        "-s",
        screenshot_path,
        "--screenshot-format",
        "png",
        "--write-none",
        "--log-scan-errors",
        "--delay",
        str(delay),
        "-T",
        str(timeout),
    ]


def execute(target: str, timeout: int = 20, delay: int = 1) -> RawGowitnessResult:
    """Executes gowitness scan single to capture a screenshot to a temp directory,
    reads the PNG bytes, deletes the temp directory, and returns RawGowitnessResult."""
    clean_target = target.strip()
    if not clean_target:
        return RawGowitnessResult(
            png_bytes=b"",
            final_url=target,
            error="empty target",
        )

    tmp_dir = tempfile.mkdtemp(prefix="tradecraft_gowitness_")
    try:
        argv = build_argv(clean_target, tmp_dir, timeout=timeout, delay=delay)
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout + 20,
            stdin=subprocess.DEVNULL,
        )

        png_files = list(Path(tmp_dir).rglob("*.png"))
        if not png_files:
            err = proc.stderr.strip() if proc.stderr else "no screenshot captured"
            return RawGowitnessResult(
                png_bytes=b"",
                final_url=clean_target,
                error=err,
            )

        png_bytes = png_files[0].read_bytes()
        return RawGowitnessResult(
            png_bytes=png_bytes,
            final_url=clean_target,
            error=None,
        )
    except FileNotFoundError:
        return RawGowitnessResult(
            png_bytes=b"",
            final_url=clean_target,
            error="gowitness executable not found",
        )
    except subprocess.TimeoutExpired:
        return RawGowitnessResult(
            png_bytes=b"",
            final_url=clean_target,
            error=f"gowitness timed out after {timeout}s",
        )
    except Exception as exc:
        return RawGowitnessResult(
            png_bytes=b"",
            final_url=clean_target,
            error=str(exc),
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
