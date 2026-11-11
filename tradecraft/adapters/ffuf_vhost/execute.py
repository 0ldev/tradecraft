"""
Raw execution: builds the ffuf vhost fuzzing argv and runs it. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import random
import string
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

import requests
import urllib3

from tradecraft.adapters.ffuf.execute import CanarySignature
from tradecraft.adapters.wordlists import resolve_wordlist


@dataclass
class RawVhostResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    json_output: str = ""
    baseline: Optional[CanarySignature] = None
    host: str = ""
    port: int = 443
    error: Optional[str] = None


def normalize_target(target: str) -> tuple[str, str, int]:
    """Parse target into (base_url, host, port)."""
    target = target.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        parsed_test = urllib.parse.urlsplit("//" + target)
        if parsed_test.port == 80:
            target = f"http://{target}"
        else:
            target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    scheme = parsed.scheme or "https"
    port = parsed.port or (80 if scheme == "http" else 443)

    base_url = f"{scheme}://{host}"
    if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        base_url += f":{parsed.port}"
    base_url += "/"
    return base_url, host, port


def probe_vhost_baseline(base_url: str, host: str, timeout: int = 15) -> Optional[CanarySignature]:
    """Capture baseline response for a random hostname prefix to learn noise signatures."""
    try:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.get(
            base_url,
            headers={
                "Host": f"{token}.{host}",
                "User-Agent": "tradecraft/vhost-baseline",
            },
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        redirect = resp.headers.get("Location")
        return CanarySignature(
            status_code=resp.status_code,
            length=len(resp.content),
            redirect_location=redirect,
        )
    except Exception:
        return None


def build_argv(base_url: str, host: str, wordlist_path: str, out_file: str) -> List[str]:
    return [
        "ffuf",
        "-u", base_url,
        "-w", wordlist_path,
        "-H", f"Host: FUZZ.{host}",
        "-mc", "200,204,301,302,307,308,401,403,500",
        "-ac",
        "-of", "json",
        "-o", out_file,
        "-s",
    ]


def execute(target: str, wordlist: str = "vhosts", timeout: int = 300) -> RawVhostResult:
    if not target or not target.strip():
        return RawVhostResult(error="Empty target")

    base_url, host, port = normalize_target(target)
    wordlist_path = resolve_wordlist(wordlist, fallback="vhosts.txt")
    if not os.path.exists(wordlist_path):
        return RawVhostResult(host=host, port=port, error=f"Wordlist not found: {wordlist_path}")

    baseline = probe_vhost_baseline(base_url, host)
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(out_fd)

    try:
        cmd = build_argv(base_url, host, wordlist_path, out_path)
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        json_out = ""
        if os.path.exists(out_path):
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                json_out = f.read()

        return RawVhostResult(
            stdout=res.stdout,
            stderr=res.stderr,
            returncode=res.returncode,
            json_output=json_out,
            baseline=baseline,
            host=host,
            port=port,
        )
    except FileNotFoundError:
        return RawVhostResult(host=host, port=port, error="ffuf binary not found")
    except subprocess.TimeoutExpired:
        return RawVhostResult(host=host, port=port, error="ffuf vhost fuzzing timed out")
    finally:
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
