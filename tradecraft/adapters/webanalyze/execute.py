"""
Raw execution: builds the webanalyze argv and runs it against one target.
No parsing here -- see parse.py.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

TECHNOLOGIES_PATH = "/tmp/technologies.json"
PREBAKED_TECHNOLOGIES_PATH = "/opt/webanalyze/technologies.json"


@dataclass
class RawWebanalyzeResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def normalize_url(target: str) -> str:
    """Bare host/'host:port' -> a URL. Defaults to http:// unless scheme is already present."""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def build_argv(target_url: str, apps_path: Optional[str] = None) -> list[str]:
    argv = ["webanalyze", "-host", target_url, "-output", "json", "-silent"]
    if apps_path:
        argv.extend(["-apps", apps_path])
    return argv


def resolve_technologies_path(apps_path: Optional[str] = None) -> Optional[str]:
    """Finds available technologies file: custom apps_path -> prebaked path -> default /tmp path."""
    if apps_path and os.path.exists(apps_path):
        return apps_path
    if os.path.exists(PREBAKED_TECHNOLOGIES_PATH):
        return PREBAKED_TECHNOLOGIES_PATH
    return apps_path or TECHNOLOGIES_PATH


def ensure_technologies_file(apps_path: str = TECHNOLOGIES_PATH, timeout: int = 60) -> None:
    """Ensure technologies definition file exists at apps_path.
    If missing, runs `webanalyze -update` in apps_path's parent directory,
    swallowing errors/timeouts so execution falls through to the scan."""
    if os.path.exists(apps_path):
        return
    parent_dir = os.path.dirname(apps_path) or "/tmp"
    try:
        subprocess.run(
            ["webanalyze", "-update"],
            cwd=parent_dir,
            capture_output=True,
            timeout=timeout,
            text=True,
            stdin=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        pass


def execute(
    target: str,
    timeout: int = 120,
    apps_path: Optional[str] = None,
) -> RawWebanalyzeResult:
    target = target.strip()
    if not target:
        return RawWebanalyzeResult(error="Target cannot be empty")

    binary = shutil.which("webanalyze")
    if not binary:
        return RawWebanalyzeResult(error="webanalyze executable not found on PATH")

    target_url = normalize_url(target)

    target_apps = resolve_technologies_path(apps_path)
    if target_apps:
        ensure_technologies_file(target_apps)

    effective_apps = target_apps if (target_apps and os.path.exists(target_apps)) else None
    argv = build_argv(target_url, apps_path=effective_apps)

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawWebanalyzeResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return RawWebanalyzeResult(error="webanalyze executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawWebanalyzeResult(error=f"webanalyze timed out after {timeout}s")
    except Exception as exc:
        return RawWebanalyzeResult(error=f"webanalyze execution failed: {str(exc)}")
