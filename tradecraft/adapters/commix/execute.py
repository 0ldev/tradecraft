"""
Raw execution: builds the commix argv and runs it against a target endpoint. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawCommixResult:
    stdout: str = ""
    stderr: str = ""
    logs_content: str = ""
    returncode: int = 0
    target_url: str = ""
    parameter: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to ensure a valid HTTP/HTTPS URL scheme."""
    target = target.strip()
    if not target:
        return ""
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target


def build_argv(
    target_url: str,
    parameter: str = "",
    data: str = "",
    method: str = "GET",
    level: int = 1,
    timeout: int = 30,
    output_dir: str = "",
) -> List[str]:
    """Builds the commix command-line invocation."""
    argv = [
        "commix",
        f"--url={target_url}",
        "--batch",
        f"--level={max(1, min(3, level))}",
        f"--timeout={max(5, timeout)}",
        "--retries=0",
    ]
    if parameter.strip():
        argv.append(f"-p={parameter.strip()}")
    if data.strip() and method.strip().upper() == "POST":
        argv.append(f"--data={data.strip()}")
    if output_dir.strip():
        argv.append(f"--output-dir={output_dir.strip()}")
    return argv


def execute(
    target: str,
    parameter: str = "",
    data: str = "",
    method: str = "GET",
    level: int = 1,
    timeout: int = 30,
) -> RawCommixResult:
    """Executes commix against a target URL."""
    target_url = normalize_target_url(target)
    if not target_url:
        return RawCommixResult(error="empty target URL")

    if shutil.which("commix") is None:
        return RawCommixResult(target_url=target_url, parameter=parameter, error="commix binary not found on PATH")

    temp_dir = tempfile.mkdtemp(prefix="commix_out_")
    argv = build_argv(
        target_url=target_url,
        parameter=parameter,
        data=data,
        method=method,
        level=level,
        timeout=timeout,
        output_dir=temp_dir,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout + 20,
        )

        logs_content = ""
        # Look for logs.txt written by commix in output directory
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file == "logs.txt" or file.endswith(".log"):
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                            logs_content = f.read()
                            break
                    except Exception:
                        pass
            if logs_content:
                break

        return RawCommixResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            logs_content=logs_content,
            returncode=proc.returncode,
            target_url=target_url,
            parameter=parameter,
        )
    except subprocess.TimeoutExpired:
        return RawCommixResult(
            target_url=target_url,
            parameter=parameter,
            error=f"commix timed out after {timeout + 20}s",
        )
    except Exception as exc:
        return RawCommixResult(
            target_url=target_url,
            parameter=parameter,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
