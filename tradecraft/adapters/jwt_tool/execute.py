"""
Execution logic for jwt_tool: automated JWT tampering, header injection,
and signature verification tests.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

SCRIPT_CANDIDATES = (
    "/opt/jwt_tool/jwt_tool.py",
    os.path.expanduser("~/jwt_tool/jwt_tool.py"),
)
DEFAULT_TIMEOUT_SECONDS = 45


@dataclass
class RawJwtToolResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    token: str = ""
    target_url: str = ""
    forged_tokens: List[str] = field(default_factory=list)
    error: Optional[str] = None


def find_script() -> Optional[str]:
    """Finds the jwt_tool.py script location."""
    for path in SCRIPT_CANDIDATES:
        if os.path.isfile(path):
            return path
    which = shutil.which("jwt_tool") or shutil.which("jwt_tool.py")
    if which:
        return which
    return None


def build_argv(
    script_path: str,
    token: str,
    target_url: str = "",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
    canary_claim: str = "",
) -> List[str]:
    """
    Builds the jwt_tool command-line invocation.
    -t: target URL to probe
    -rh: request header carrying the token
    -M at: Playbook All Tests (alg:none, signature stripping, key confusion, kid injection)
    """
    cmd = ["python3", script_path, token]
    if target_url.strip():
        cmd.extend(["-t", target_url.strip()])
        header_val = f"{header_prefix}{token}".strip()
        cmd.extend(["-rh", f"{header_name}: {header_val}"])
        # Automated playbook mode: test common tamper bypasses against endpoint
        cmd.extend(["-M", "at"])
    else:
        # Offline analysis / tampering generation mode
        cmd.extend(["-M", "at", "--bare"])

    if canary_claim.strip():
        cmd.extend(["-pc", canary_claim.strip()])

    return cmd


def execute(
    token: str,
    target_url: str = "",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
    canary_claim: str = "",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RawJwtToolResult:
    """Executes jwt_tool against a token and optional target URL."""
    clean_token = token.strip()
    if not clean_token:
        return RawJwtToolResult(error="empty JWT token")

    parts = clean_token.split(".")
    if len(parts) < 2:
        return RawJwtToolResult(token=clean_token, error="invalid JWT format: expected at least header and payload segments")

    script = find_script()
    if not script:
        return RawJwtToolResult(
            token=clean_token,
            error=f"jwt_tool not found at {SCRIPT_CANDIDATES[0]}",
        )

    argv = build_argv(
        script_path=script,
        token=clean_token,
        target_url=target_url,
        header_name=header_name,
        header_prefix=header_prefix,
        canary_claim=canary_claim,
    )

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawJwtToolResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            token=clean_token,
            target_url=target_url.strip(),
        )
    except FileNotFoundError:
        return RawJwtToolResult(token=clean_token, error="python3 binary not found")
    except subprocess.TimeoutExpired:
        return RawJwtToolResult(token=clean_token, error=f"jwt_tool execution timed out after {timeout}s")
    except Exception as exc:
        return RawJwtToolResult(token=clean_token, error=f"jwt_tool execution failed: {exc}")
