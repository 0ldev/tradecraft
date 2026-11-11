"""
Raw execution: builds the wpscan argv and runs it against a target WordPress site.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawWPScanResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
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

    # If scheme is http on default port, prefer https
    parts = urllib.parse.urlsplit(target)
    if parts.scheme == "http" and not parts.port:
        target = urllib.parse.urlunsplit(parts._replace(scheme="https"))

    if not target.endswith("/"):
        target = f"{target}/"
    return target


def has_vulnerability_api_token(api_token: str = "") -> bool:
    """True if a WPScan API token is available (param or WPSCAN_API_TOKEN env
    var) -- the vp/vt (vulnerable plugins/themes) enumerate flags, and the
    site's own vulnerability counts, require one. Shared with the tool layer
    so a result can say when vulnerability lookup was skipped instead of a
    skipped lookup looking identical to a confirmed-zero count."""
    return bool(api_token or os.environ.get("WPSCAN_API_TOKEN"))


def build_argv(
    target_url: str,
    enumerate: str = "u",
    detection_mode: str = "passive",
    api_token: str = "",
    disable_tls_checks: bool = True,
) -> List[str]:
    argv = [
        "wpscan",
        "--url",
        target_url,
        "--format",
        "json",
        "--random-user-agent",
        "--no-update",
    ]
    if disable_tls_checks:
        argv.append("--disable-tls-checks")

    if detection_mode:
        argv.extend(["--plugins-detection", detection_mode])
        argv.extend(["--themes-detection", detection_mode])
    argv.extend(["--users-detection", "passive"])

    # "vp" (vulnerable plugins) and "vt" (vulnerable themes) require an API token;
    # without one the entire scan aborts. Only include them when an API token is present.
    has_token = has_vulnerability_api_token(api_token)
    enum_parts = [p.strip() for p in enumerate.split(",") if p.strip()]
    if not has_token:
        enum_parts = [p for p in enum_parts if p not in ("vp", "vt")]

    if enum_parts:
        argv.extend(["--enumerate", ",".join(enum_parts)])

    if api_token:
        argv.extend(["--api-token", api_token])
    elif os.environ.get("WPSCAN_API_TOKEN"):
        argv.extend(["--api-token", os.environ["WPSCAN_API_TOKEN"]])

    return argv


def execute(
    target: str,
    enumerate: str = "u",
    detection_mode: str = "passive",
    api_token: str = "",
    disable_tls_checks: bool = True,
    subprocess_timeout: int = 180,
) -> RawWPScanResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawWPScanResult(error="Target cannot be empty")

    binary = shutil.which("wpscan")
    if not binary:
        return RawWPScanResult(
            target_url=target_url,
            error="wpscan binary not found on PATH. Install wpscan to enable WordPress scanning.",
        )

    try:
        argv = build_argv(
            target_url=target_url,
            enumerate=enumerate,
            detection_mode=detection_mode,
            api_token=api_token,
            disable_tls_checks=disable_tls_checks,
        )

        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=subprocess_timeout,
        )

        # WPScan exit codes: 0 = clean, 5 = vulnerabilities found.
        # Both are successful scans.
        if proc.returncode not in (0, 5) and not proc.stdout.strip().startswith("{"):
            stderr_snippet = (proc.stderr or proc.stdout).strip()[-400:]
            return RawWPScanResult(
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                returncode=proc.returncode,
                target_url=target_url,
                error=f"wpscan exited with error code {proc.returncode}: {stderr_snippet}",
            )

        return RawWPScanResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target_url=target_url,
        )
    except subprocess.TimeoutExpired:
        return RawWPScanResult(
            target_url=target_url,
            error=f"wpscan execution timed out after {subprocess_timeout}s against {target_url}",
        )
    except Exception as e:
        return RawWPScanResult(
            target_url=target_url,
            error=f"wpscan execution failed: {str(e)}",
        )
