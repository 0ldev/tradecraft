"""
Raw execution: builds the httpx argv and runs it against one or multiple targets.
No parsing here -- that's parse.py's job. httpx exits non-zero even for a
routine "host didn't answer" outcome, so execute() doesn't treat that as
a failure; parse.py reports liveness from whatever JSON line (if any)
came back on stdout.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawProbeResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None  # set only on a genuine execution failure


def normalize_targets(target: str) -> List[str]:
    """Comma-split and trim targets, preserving order and removing duplicates.
    Can handle bare hosts, host:port, or full URLs."""
    seen = set()
    hosts = []
    for t in target.split(","):
        s = t.strip()
        if s and s not in seen:
            seen.add(s)
            hosts.append(s)
    return hosts


def _header_args(headers: Optional[str]) -> List[str]:
    """Each non-empty newline-separated line becomes its own '-H' flag,
    same header-string convention as http_request's `headers` parameter."""
    if not headers:
        return []
    args: List[str] = []
    for line in headers.split("\n"):
        line = line.strip()
        if line:
            args.extend(["-H", line])
    return args


def build_argv_single(target: str, headers: Optional[str] = None) -> List[str]:
    # Installed as 'pd-httpx' -- see config/tools/httpx_probe.yaml for why.
    return [
        "pd-httpx", "-u", target, "-silent", "-json", "-include-response-header",
        "-timeout", "10", "-retries", "1", "-follow-redirects",
        *_header_args(headers),
    ]


def build_argv_bulk(hosts_file: str, headers: Optional[str] = None) -> List[str]:
    return [
        "pd-httpx", "-l", hosts_file, "-silent", "-json", "-include-response-header",
        "-timeout", "10", "-retries", "1", "-follow-redirects",
        "-rate-limit", "25", "-threads", "10",
        *_header_args(headers),
    ]


def build_argv(target: str, headers: Optional[str] = None) -> List[str]:
    """Backward compatibility helper for single target."""
    return build_argv_single(target, headers)


def execute(target: str, timeout: int = 30, headers: Optional[str] = None) -> RawProbeResult:
    hosts = normalize_targets(target)
    if not hosts:
        return RawProbeResult(error="missing target")

    tmp_file = None
    try:
        if len(hosts) == 1:
            argv = build_argv_single(hosts[0], headers)
            eff_timeout = timeout
        else:
            eff_timeout = min(max(timeout, 5 * len(hosts)), 180)
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                for h in hosts:
                    f.write(f"{h}\n")
                tmp_file = f.name
            argv = build_argv_bulk(tmp_file, headers)

        # stdin=DEVNULL: httpx reads piped stdin targets in addition to -u/-l --
        # inheriting this process's own stdin (a tty when run interactively)
        # makes it block forever waiting for input that will never arrive.
        process = subprocess.run(
            argv, text=True, capture_output=True, timeout=eff_timeout, stdin=subprocess.DEVNULL,
        )
        return RawProbeResult(stdout=process.stdout, stderr=process.stderr, returncode=process.returncode)
    except FileNotFoundError:
        return RawProbeResult(error="httpx executable not found")
    except subprocess.TimeoutExpired:
        timeout_val = eff_timeout if len(hosts) > 1 else timeout
        return RawProbeResult(error=f"httpx timed out after {timeout_val}s")
    finally:
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass
