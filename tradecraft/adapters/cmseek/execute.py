"""
Subprocess execution for CMSeeK: multi-CMS detection, version fingerprinting,
and asset discovery across 180+ Content Management Systems.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT_SECONDS = 180
CMSEEK_SCRIPT_ENV = "CMSEEK_SCRIPT_PATH"
CMSEEK_SCRIPT_DEFAULT = "/opt/cmseek/cmseek.py"

SCRIPT_CANDIDATES = (
    "/opt/cmseek/cmseek.py",
    os.path.expanduser("~/cmseek/cmseek.py"),
)


@dataclass
class RawCMSeeKResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    json_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def find_script() -> Optional[str]:
    """Finds the cmseek.py script location."""
    env_path = os.environ.get(CMSEEK_SCRIPT_ENV)
    if env_path and os.path.isfile(env_path):
        return env_path
    for p in SCRIPT_CANDIDATES:
        if os.path.isfile(p):
            return p
    which = shutil.which("cmseek")
    if which:
        return which
    return None


def normalize_target_url(target: str) -> str:
    """Normalizes target to have http/https scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def extract_host_from_target(target_url: str) -> str:
    """Extracts hostname from target URL for locating Result/<host>/cms.json."""
    parsed = urllib.parse.urlsplit(target_url)
    host = parsed.netloc or parsed.path
    if ":" in host:
        host = host.split(":")[0]
    return host


def build_argv(
    target_url: str,
    follow_redirect: bool = True,
    light_scan: bool = False,
    only_cms: bool = False,
    script: str = CMSEEK_SCRIPT_DEFAULT,
) -> List[str]:
    """Builds cmseek execution argv."""
    cmd = ["python3", script, "-u", target_url.strip(), "--batch"]
    if follow_redirect:
        cmd.append("--follow-redirect")
    if light_scan:
        cmd.append("--light-scan")
    if only_cms:
        cmd.append("-o")
    return cmd


def execute(
    target: str,
    follow_redirect: bool = True,
    light_scan: bool = False,
    only_cms: bool = False,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RawCMSeeKResult:
    """Executes CMSeeK against the target URL and reads structured results."""
    target_url = normalize_target_url(target)
    if not target_url:
        return RawCMSeeKResult(error="empty target")

    script = find_script()
    if not script:
        return RawCMSeeKResult(
            target_url=target_url,
            error=f"cmseek script not found (checked {CMSEEK_SCRIPT_DEFAULT})",
        )

    script_dir = os.path.dirname(os.path.abspath(script))
    cmd = build_argv(
        target_url=target_url,
        follow_redirect=follow_redirect,
        light_scan=light_scan,
        only_cms=only_cms,
        script=script,
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=script_dir,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return RawCMSeeKResult(
            target_url=target_url,
            error=f"cmseek execution timed out after {timeout}s against {target_url}",
        )
    except Exception as e:
        return RawCMSeeKResult(
            target_url=target_url,
            error=f"cmseek execution failed: {e}",
        )

    host = extract_host_from_target(target_url)
    json_path = Path(script_dir) / "Result" / host / "cms.json"
    json_data: Dict[str, Any] = {}

    if json_path.is_file():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
        except Exception:
            pass

    return RawCMSeeKResult(
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
        target_url=target_url,
        json_data=json_data,
    )
