"""
Raw execution: builds the dalfox argv and runs it against one target endpoint.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

from tradecraft.adapters.partial_output import from_timeout


@dataclass
class RawDalfoxResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    json_content: str = ""
    error: Optional[str] = None
    # True when the subprocess was killed at its timeout. stdout/stderr then
    # hold only what was written before the kill.
    timed_out: bool = False
    timeout_seconds: Optional[int] = None


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
    cookie: str = "",
    header: str = "",
    output_file: str = "",
    timeout: int = 10,
    scan_timeout: int = 20,
) -> List[str]:
    argv = [
        "dalfox",
        "scan",
        target_url,
        "-i",
        "url",
        "-f",
        "json",
        "--no-color",
    ]
    if output_file:
        argv.extend(["-o", output_file])
    if parameter:
        argv.extend(["-p", parameter])
    if data:
        argv.extend(["-d", data])
    if method and method.upper() != "GET":
        argv.extend(["-X", method.upper()])
    if cookie:
        argv.extend(["--cookies", cookie])
    if header:
        argv.extend(["-H", header])
    if timeout > 0:
        argv.extend(["--timeout", str(timeout)])
    if scan_timeout > 0:
        argv.extend(["--scan-timeout", str(scan_timeout)])
    return argv


def execute(
    target: str,
    parameter: str = "",
    data: str = "",
    method: str = "GET",
    cookie: str = "",
    header: str = "",
    timeout: int = 10,
    scan_timeout: int = 20,
    subprocess_timeout: int = 45,
) -> RawDalfoxResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawDalfoxResult(error="Target cannot be empty")

    binary = shutil.which("dalfox")
    if not binary:
        return RawDalfoxResult(
            error="dalfox binary not found on PATH. Install dalfox to enable XSS testing."
        )

    tmp_dir = tempfile.mkdtemp(prefix="dalfox_")
    out_file = os.path.join(tmp_dir, "output.json")
    try:
        argv = build_argv(
            target_url=target_url,
            parameter=parameter,
            data=data,
            method=method,
            cookie=cookie,
            header=header,
            output_file=out_file,
            timeout=timeout,
            scan_timeout=scan_timeout,
        )

        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=subprocess_timeout,
        )

        json_content = ""
        if os.path.exists(out_file):
            try:
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    json_content = f.read()
            except OSError:
                pass

        return RawDalfoxResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target_url=target_url,
            json_content=json_content,
        )
    except subprocess.TimeoutExpired as exc:
        # dalfox writes its JSON report only at the end, so a killed run
        # usually has progress text on stdout and no report file.
        stdout, stderr = from_timeout(exc)
        return RawDalfoxResult(
            stdout=stdout,
            stderr=stderr,
            error=f"dalfox execution timed out after {subprocess_timeout}s against {target_url}",
            target_url=target_url,
            timed_out=True,
            timeout_seconds=subprocess_timeout,
        )
    except Exception as e:
        return RawDalfoxResult(
            error=f"dalfox execution failed: {str(e)}",
            target_url=target_url,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
