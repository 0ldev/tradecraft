"""
Raw execution: builds the sqlmap argv and runs it against one target endpoint.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawSqlmapResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    parameter: str = ""
    csv_content: str = ""
    log_content: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not (target.startswith("http://") or target.startswith("https://")):
        parsed = urllib.parse.urlsplit("//" + target)
        if parsed.port == 80:
            target = f"http://{target}"
        elif parsed.port == 443:
            target = f"https://{target}"
        else:
            target = f"https://{target}"
    return target


def build_argv(
    target_url: str,
    parameter: str = "",
    data: str = "",
    method: str = "GET",
    level: int = 1,
    risk: int = 1,
    output_dir: str = "",
    timeout: int = 10,
    threads: int = 2,
    smart: bool = True,
) -> List[str]:
    argv = [
        "sqlmap",
        "-u",
        target_url,
        "--batch",
        "--random-agent",
        f"--timeout={max(3, timeout)}",
        "--retries=1",
        f"--level={max(1, min(5, level))}",
        f"--risk={max(1, min(3, risk))}",
        f"--threads={max(1, min(10, threads))}",
    ]

    if smart:
        argv.append("--smart")

    if parameter:
        argv.extend(["-p", parameter])

    m = method.strip().upper()
    if m == "POST" and data:
        argv.extend(["--data", data])
    elif m == "POST" and not data:
        argv.extend(["--method=POST"])

    if output_dir:
        argv.extend(["--output-dir", output_dir])

    return argv


def execute(
    target: str,
    parameter: str = "",
    data: str = "",
    method: str = "GET",
    level: int = 1,
    risk: int = 1,
    timeout_per_request: int = 10,
    overall_timeout: Optional[int] = None,
) -> RawSqlmapResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawSqlmapResult(error="empty target")

    if shutil.which("sqlmap") is None:
        return RawSqlmapResult(target_url=target_url, error="sqlmap binary not found on PATH")

    effective_timeout = overall_timeout if overall_timeout is not None else 60
    tmp_dir = tempfile.mkdtemp(prefix="sqlmap_run_")

    argv = build_argv(
        target_url=target_url,
        parameter=parameter,
        data=data,
        method=method,
        level=level,
        risk=risk,
        output_dir=tmp_dir,
        timeout=timeout_per_request,
    )

    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
        duration = time.monotonic() - start

        csv_content = ""
        log_content = ""

        if os.path.exists(tmp_dir):
            for fname in os.listdir(tmp_dir):
                if fname.startswith("results-") and fname.endswith(".csv"):
                    try:
                        with open(os.path.join(tmp_dir, fname), "r", encoding="utf-8", errors="replace") as f:
                            csv_content = f.read()
                    except OSError:
                        pass
                    break

            parsed = urllib.parse.urlsplit(target_url)
            host = parsed.hostname or ""
            if host:
                host_log_path = os.path.join(tmp_dir, host, "log")
                if os.path.exists(host_log_path):
                    try:
                        with open(host_log_path, "r", encoding="utf-8", errors="replace") as f:
                            log_content = f.read()
                    except OSError:
                        pass

        return RawSqlmapResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
            parameter=parameter,
            csv_content=csv_content,
            log_content=log_content,
            duration_seconds=duration,
            error=f"sqlmap exited with status {proc.returncode}" if proc.returncode != 0 else None,
        )
    except subprocess.TimeoutExpired:
        return RawSqlmapResult(
            target_url=target_url,
            parameter=parameter,
            duration_seconds=time.monotonic() - start,
            error=f"sqlmap timed out after {effective_timeout}s",
        )
    except Exception as exc:
        return RawSqlmapResult(
            target_url=target_url,
            parameter=parameter,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
