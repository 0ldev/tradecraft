from __future__ import annotations

import atexit
import ctypes
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.interactsh.parse import parse_interactions_jsonl

DEFAULT_SERVER = "oast.me"
DEFAULT_POLL_INTERVAL = 2

# Namespaced by this process's own PID -- a prior engagement process
# (a different PID) can never hand this one a stale daemon/domain/
# output file left behind in shared /tmp paths. Within one engagement
# process (one PID, many turns), the same files persist across
# generate/poll calls as before.
_PID = os.getpid()
PID_FILE = f"/tmp/tradecraft_interactsh_{_PID}_daemon.pid"
DOMAIN_FILE = f"/tmp/tradecraft_interactsh_{_PID}_domain.txt"
OUTPUT_FILE = f"/tmp/tradecraft_interactsh_{_PID}_interactions.jsonl"
LOG_FILE = f"/tmp/tradecraft_interactsh_{_PID}.log"
GENERATED_AT_FILE = f"/tmp/tradecraft_interactsh_{_PID}_generated_at.txt"

_DAEMON_PROC: Optional[subprocess.Popen] = None


def _set_pdeathsig() -> None:
    """On Linux, ask the kernel to send SIGTERM to the child if the parent dies."""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG = 1
    except Exception:
        pass


def is_daemon_running() -> Tuple[bool, Optional[int]]:
    if not os.path.exists(PID_FILE):
        return False, None
    try:
        pid = int(Path(PID_FILE).read_text().strip())
        if _DAEMON_PROC is not None and _DAEMON_PROC.pid == pid:
            if _DAEMON_PROC.poll() is not None:
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
                return False, None
        os.kill(pid, 0)
        return True, pid
    except (ValueError, OSError):
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return False, None


def stop_daemon() -> bool:
    global _DAEMON_PROC
    running, pid = is_daemon_running()
    if running and pid:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        except OSError:
            pass

    if _DAEMON_PROC is not None:
        try:
            if _DAEMON_PROC.poll() is None:
                _DAEMON_PROC.terminate()
                try:
                    _DAEMON_PROC.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    _DAEMON_PROC.kill()
                    _DAEMON_PROC.wait(timeout=1)
            else:
                _DAEMON_PROC.wait(timeout=1)
        except Exception:
            pass
        _DAEMON_PROC = None

    for f in (PID_FILE, DOMAIN_FILE, OUTPUT_FILE, GENERATED_AT_FILE, LOG_FILE):
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass
    return True


atexit.register(stop_daemon)


def start_daemon(
    server: str = DEFAULT_SERVER,
    poll_interval: int = DEFAULT_POLL_INTERVAL,
    binary: str = "interactsh-client",
) -> Tuple[Optional[str], Optional[str]]:
    """Starts the interactsh-client background daemon and returns (domain, error)."""
    global _DAEMON_PROC
    running, _ = is_daemon_running()
    if running and os.path.exists(DOMAIN_FILE):
        try:
            existing_domain = Path(DOMAIN_FILE).read_text().strip()
            if existing_domain:
                return existing_domain, None
        except Exception:
            pass

    if shutil.which(binary) is None:
        return None, f"required binary '{binary}' not found on PATH"

    # Reset state files (stop_daemon() already clears PID/DOMAIN/OUTPUT/
    # GENERATED_AT/LOG for this PID; nothing left to do here).
    stop_daemon()

    cmd = [
        binary,
        "-server",
        server,
        "-o",
        OUTPUT_FILE,
        "-json",
        "-pi",
        str(max(1, poll_interval)),
    ]

    try:
        with open(LOG_FILE, "w", encoding="utf-8") as log_fh:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=_set_pdeathsig if sys.platform.startswith("linux") else None,
            )
        _DAEMON_PROC = proc
    except Exception as exc:
        stop_daemon()
        return None, f"failed to spawn {binary}: {exc}"

    domain: Optional[str] = None
    start_time = time.time()
    # Poll LOG_FILE until domain is captured or 15s timeout expires
    while time.time() - start_time < 15:
        log_text = ""
        if os.path.exists(LOG_FILE):
            try:
                log_text = Path(LOG_FILE).read_text(encoding="utf-8", errors="replace")
            except OSError:
                log_text = ""
        match = re.search(r"([a-z0-9]{20,}\.oast\.[a-z]+)", log_text)
        if match:
            domain = match.group(1).strip()
            break
        if proc.poll() is not None:
            stop_daemon()
            return None, f"interactsh-client exited prematurely: {log_text.strip()}"
        time.sleep(0.2)

    if not domain:
        stop_daemon()
        return None, "timed out waiting for interactsh payload domain registration"

    # Persist PID, domain, and this domain's own creation time -- the
    # reference point poll() uses to tell the model whether a given
    # interaction could possibly have been caused by a request sent
    # during this engagement, rather than leaving that arithmetic to
    # the model.
    Path(PID_FILE).write_text(str(proc.pid))
    Path(DOMAIN_FILE).write_text(domain)
    Path(GENERATED_AT_FILE).write_text(datetime.now(timezone.utc).isoformat())
    return domain, None


def execute(
    action: str,
    server: str = DEFAULT_SERVER,
    poll_interval: int = DEFAULT_POLL_INTERVAL,
    binary: str = "interactsh-client",
) -> Dict[str, Any]:
    act = (action or "generate").strip().lower()

    if act in ("generate", "start"):
        domain, err = start_daemon(server=server, poll_interval=poll_interval, binary=binary)
        if err:
            return {"action": "generate", "active": False, "error": err}
        return {
            "action": "generate",
            "active": True,
            "payload_domain": domain,
            "payload_url": f"http://{domain}",
            "server": server,
        }

    if act == "poll":
        running, _ = is_daemon_running()
        domain = ""
        if os.path.exists(DOMAIN_FILE):
            domain = Path(DOMAIN_FILE).read_text().strip()
        generated_at = ""
        if os.path.exists(GENERATED_AT_FILE):
            generated_at = Path(GENERATED_AT_FILE).read_text().strip()

        interactions: List[Dict[str, Any]] = []
        if os.path.exists(OUTPUT_FILE):
            try:
                content = Path(OUTPUT_FILE).read_text(encoding="utf-8", errors="replace")
                interactions = parse_interactions_jsonl(content, generated_at=generated_at)
            except Exception as exc:
                return {
                    "action": "poll",
                    "active": running,
                    "payload_domain": domain,
                    "error": f"failed to read interactions file: {exc}",
                }

        return {
            "action": "poll",
            "active": running,
            "payload_domain": domain,
            "payload_domain_generated_at": generated_at,
            "total_interactions": len(interactions),
            "interactions": interactions,
        }

    if act == "status":
        running, pid = is_daemon_running()
        domain = ""
        if os.path.exists(DOMAIN_FILE):
            domain = Path(DOMAIN_FILE).read_text().strip()
        return {
            "action": "status",
            "active": running,
            "pid": pid,
            "payload_domain": domain,
            "payload_url": f"http://{domain}" if domain else "",
        }

    if act == "stop":
        stopped = stop_daemon()
        return {"action": "stop", "active": False, "stopped": stopped}

    return {"action": act, "error": f"unknown interactsh action: '{action}'"}
