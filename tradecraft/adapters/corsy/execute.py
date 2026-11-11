"""
Subprocess execution for corsy.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawCorsyResult:
    url: str
    stdout: str
    stderr: str
    returncode: int
    error: Optional[str] = None


def build_argv(url: str, output_path: str, headers: Optional[str] = None) -> List[str]:
    argv = ["corsy", "-u", url, "-o", output_path]
    if headers:
        header_dict = {
            k.strip(): v.strip()
            for k, v in (line.split(":", 1) for line in headers.splitlines() if ":" in line)
        }
        if header_dict:
            argv.extend(["--headers", json.dumps(header_dict)])
    return argv


def execute(url: str, headers: Optional[str] = None, timeout: int = 30) -> RawCorsyResult:
    """Writes to a temporary JSON file path, runs build_argv(), and reads
    back the file's contents into RawCorsyResult.stdout."""
    clean_url = url.strip()
    if not clean_url:
        return RawCorsyResult(url=url, stdout="", stderr="empty url", returncode=1, error="empty url")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        argv = build_argv(clean_url, tmp_path, headers=headers)
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

        stdout_content = ""
        if os.path.exists(tmp_path):
            with open(tmp_path, "r", encoding="utf-8") as f:
                stdout_content = f.read()

        return RawCorsyResult(
            url=clean_url,
            stdout=stdout_content,
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            error=None,
        )
    except FileNotFoundError:
        return RawCorsyResult(
            url=clean_url,
            stdout="",
            stderr="",
            returncode=-1,
            error="corsy executable not found",
        )
    except subprocess.TimeoutExpired:
        return RawCorsyResult(
            url=clean_url,
            stdout="",
            stderr="",
            returncode=-1,
            error=f"corsy timed out after {timeout}s",
        )
    except Exception as exc:
        return RawCorsyResult(
            url=clean_url,
            stdout="",
            stderr="",
            returncode=-1,
            error=str(exc),
        )
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
