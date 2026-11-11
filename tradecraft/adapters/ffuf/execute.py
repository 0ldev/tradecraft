"""
Raw execution: builds the ffuf argv and runs it against one target. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple, Union

import requests
import urllib3

from tradecraft.adapters.wordlists import resolve_wordlist

# ffuf's own default (`-t`, 40 concurrent threads, no inter-request delay) is
# too aggressive to run unconditionally against a shared-hosting target --
# stacking it with other concurrent tool calls can trip a host's connection-
# flood protection and end active testing early. This hard cap -- independent
# of any model-facing parameter, same shape as nuclei's own unexposed
# `-rl`/`-c` defaults -- bounds every call's worst case regardless of what
# the model asks for.
DEFAULT_THREADS = 10
MAX_THREADS = 10


@dataclass
class CanarySignature:
    status_code: int
    length: int
    redirect_location: Optional[str] = None


@dataclass
class RawFfufResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    json_output: str = ""
    canary: Optional[CanarySignature] = None
    target_url: str = ""
    requests_attempted: int = 0
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
        else:
            target = f"https://{target}"

    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"
    return target


def normalize_extensions(extensions: Union[str, List[str], Any]) -> str:
    if isinstance(extensions, list):
        raw_exts = extensions
    elif isinstance(extensions, str):
        raw_exts = extensions.split(",")
    else:
        return ""

    clean_exts = []
    for ext in raw_exts:
        s = str(ext).strip()
        if not s:
            continue
        if not s.startswith("."):
            s = f".{s}"
        clean_exts.append(s)
    return ",".join(clean_exts)


def probe_canary(base_url: str) -> Optional[CanarySignature]:
    """Probe a guaranteed non-existent path to detect uniform WAF / catch-all responses."""
    try:
        token = secrets.token_hex(12)
        canary_url = base_url.rstrip("/") + f"/{token}-tradecraft-canary"
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.get(canary_url, timeout=10, verify=False, allow_redirects=False)
        redirect = resp.headers.get("Location")
        return CanarySignature(
            status_code=resp.status_code,
            length=len(resp.content),
            redirect_location=redirect,
        )
    except Exception:
        return None


def count_wordlist_requests(wordlist_path: str, extensions: Union[str, List[str]] = "") -> int:
    """Deterministic request-volume estimate: ffuf fires one request per
    non-blank wordlist line, plus one more per extension appended to that
    line. Used to give the model a concrete number instead of a qualitative
    'this might be heavy' guess."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
            word_count = sum(1 for line in f if line.strip())
    except OSError:
        return 0
    norm_ext = normalize_extensions(extensions)
    num_ext = len([e for e in norm_ext.split(",") if e]) if norm_ext else 0
    return word_count * (1 + num_ext)


def build_argv(
    target_url: str,
    wordlist_path: str,
    out_file: str,
    extensions: Union[str, List[str]] = "",
    match_codes: str = "all",
    filter_codes: str = "404",
    threads: int = DEFAULT_THREADS,
) -> List[str]:
    cmd = [
        "ffuf",
        "-u", target_url,
        "-w", wordlist_path,
        "-mc", match_codes,
        "-fc", filter_codes,
        "-of", "json",
        "-o", out_file,
        "-t", str(max(1, min(MAX_THREADS, threads))),
        "-s",
    ]
    norm_ext = normalize_extensions(extensions)
    if norm_ext:
        cmd.extend(["-e", norm_ext])
    return cmd


def execute(
    target: str,
    wordlist: str = "common",
    extensions: Union[str, List[str]] = "",
    match_codes: str = "all",
    filter_codes: str = "404",
    timeout: int = 60,
) -> RawFfufResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawFfufResult(error="Missing or empty target")

    wordlist_path = resolve_wordlist(wordlist)
    if not os.path.isfile(wordlist_path):
        return RawFfufResult(error=f"Wordlist not found: {wordlist_path}")

    base_url = target_url.split("FUZZ")[0].rstrip("/")
    canary = probe_canary(base_url)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    requests_attempted = count_wordlist_requests(wordlist_path, extensions)
    start = time.monotonic()
    try:
        cmd = build_argv(
            target_url=target_url,
            wordlist_path=wordlist_path,
            out_file=out_file,
            extensions=extensions,
            match_codes=match_codes,
            filter_codes=filter_codes,
        )
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        duration = time.monotonic() - start
        json_content = Path(out_file).read_text(encoding="utf-8", errors="replace") if Path(out_file).exists() else ""
        return RawFfufResult(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
            json_output=json_content,
            canary=canary,
            target_url=target_url,
            requests_attempted=requests_attempted,
            duration_seconds=duration,
        )
    except FileNotFoundError:
        return RawFfufResult(error="ffuf executable not found", canary=canary, target_url=target_url)
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        return RawFfufResult(
            error=f"ffuf timed out after {timeout}s",
            canary=canary,
            target_url=target_url,
            requests_attempted=requests_attempted,
            duration_seconds=duration,
        )
    finally:
        if os.path.exists(out_file):
            try:
                os.remove(out_file)
            except OSError:
                pass
