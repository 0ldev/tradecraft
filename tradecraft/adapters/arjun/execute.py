"""
Raw execution: builds the arjun argv and runs it against one target endpoint.
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


@dataclass
class RawArjunResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    json_output: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str, path: str = "/") -> str:
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

    parsed = urllib.parse.urlsplit(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    target_path = parsed.path
    if path and path != "/":
        full_path = path
    elif target_path and target_path != "/":
        full_path = target_path
    else:
        full_path = "/"

    if not full_path.startswith("/"):
        full_path = "/" + full_path

    return f"{base}{full_path}"


def build_argv(
    target_url: str,
    method: str = "GET",
    wordlist: str = "small",
    json_out_path: str = "",
    threads: int = 5,
    timeout: int = 10,
) -> List[str]:
    # Arjun supports GET, POST, JSON, XML
    m = method.strip().upper()
    if m not in ("GET", "POST", "JSON", "XML"):
        m = "GET"

    wl = wordlist.strip().lower()
    if wl not in ("small", "medium", "large"):
        wl = "small"

    argv = [
        "arjun",
        "-u",
        target_url,
        "-m",
        m,
        "-w",
        wl,
        "-t",
        str(max(1, threads)),
        "-T",
        str(max(3, timeout)),
    ]
    if json_out_path:
        argv.extend(["-o", json_out_path])
    return argv


def execute(
    target: str,
    path: str = "/",
    method: str = "GET",
    wordlist: str = "small",
    threads: int = 5,
    timeout_per_request: int = 10,
    overall_timeout: Optional[int] = None,
) -> RawArjunResult:
    target_url = normalize_target_url(target, path=path)
    if not target_url:
        return RawArjunResult(error="empty target")

    if shutil.which("arjun") is None:
        return RawArjunResult(target_url=target_url, error="arjun binary not found on PATH")

    effective_timeout = overall_timeout if overall_timeout is not None else 60

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="arjun_out_", suffix=".json")
    os.close(tmp_fd)

    argv = build_argv(
        target_url=target_url,
        method=method,
        wordlist=wordlist,
        json_out_path=tmp_path,
        threads=threads,
        timeout=timeout_per_request,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )

        json_content = ""
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            try:
                with open(tmp_path, "r", encoding="utf-8") as f:
                    json_content = f.read()
            except OSError:
                pass

        return RawArjunResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
            json_output=json_content,
            error=f"arjun exited with status {proc.returncode}" if proc.returncode != 0 else None,
        )
    except subprocess.TimeoutExpired:
        json_content = ""
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            try:
                with open(tmp_path, "r", encoding="utf-8") as f:
                    json_content = f.read()
            except OSError:
                pass
        return RawArjunResult(
            target_url=target_url,
            json_output=json_content,
            error=f"arjun timed out after {effective_timeout}s",
        )
    except Exception as exc:
        return RawArjunResult(
            target_url=target_url,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
