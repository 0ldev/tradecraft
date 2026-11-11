"""
Execution logic for SSTI detection via tplmap / sstimap.
Runs detection mode only (-u target_url) without any exploitation flags.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Optional

SCRIPT_PATH = "/opt/tplmap/tplmap.py"
SCRIPT_CANDIDATES = (
    "/opt/tplmap/tplmap.py",
    "/opt/tplmap/sstimap.py",
    "/opt/SSTImap/sstimap.py",
)


@dataclass
class RawTplmapResult:
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None


def find_script() -> Optional[str]:
    """Finds the tplmap or sstimap script location."""
    for path in SCRIPT_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def execute(target_url: str, timeout: int = 300) -> RawTplmapResult:
    """Executes tplmap in detection-only mode against a target URL."""
    script = find_script()
    if not script:
        return RawTplmapResult(error=f"tplmap not found at {SCRIPT_PATH}")

    # Plain detection mode: -u target_url, strictly no --os-cmd or exploitation flags.
    cmd = ["python3", script, "-u", target_url, "--no-color"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawTplmapResult(stdout=proc.stdout, stderr=proc.stderr)
    except FileNotFoundError:
        return RawTplmapResult(error="python3 binary not found")
    except subprocess.TimeoutExpired:
        return RawTplmapResult(error="tplmap execution timed out")
    except Exception as exc:
        return RawTplmapResult(error=str(exc))
