"""
Raw execution: builds the testssl argv and runs it, writing CSV findings
to a temp file (testssl's own CLI writes structured output to a file,
not stdout). Cleanup happens here since parse.py stays I/O-free.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawTlsAuditResult:
    csv_output: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def build_argv(target: str, out_path: str) -> list[str]:
    return [
        "testssl", "--csvfile", out_path, "-q", "--fast",
        "--connect-timeout", "5", "--openssl-timeout", "5",
        "--protocols", "--headers", target,
    ]


def execute(target: str, timeout: int = 90) -> RawTlsAuditResult:
    fd, out_path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        try:
            process = subprocess.run(
                build_argv(target, out_path), text=True, capture_output=True, timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return RawTlsAuditResult(error="testssl executable not found")
        except subprocess.TimeoutExpired:
            return RawTlsAuditResult(error=f"testssl timed out after {timeout}s")

        # testssl exits 2 when some individual checks failed/were skipped --
        # still a valid run with real findings, not an execution failure.
        if process.returncode not in (0, 2):
            return RawTlsAuditResult(
                stderr=process.stderr, returncode=process.returncode,
                error=f"testssl failed: {(process.stderr or process.stdout).strip()[:500]}",
            )

        csv_output = ""
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, encoding="utf-8", errors="replace") as f:
                csv_output = f.read()
        return RawTlsAuditResult(csv_output=csv_output, stderr=process.stderr, returncode=process.returncode)
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)
