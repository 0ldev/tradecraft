"""
Raw execution: validates the inputs, builds the nmap argv, and runs it.
Does no parsing of the output -- that's `parse.py`'s job.

Guards:
  * The NSE script filter is a single boolean category expression, not a
    bare category list: `--script vuln,safe` would still execute dos/
    exploit/brute/intrusive scripts that also happen to carry a vuln or
    safe tag.
  * `ports` is required and explicit, capped at MAX_PORTS per call. No
    full-range NSE sweeps.
  * XML output (`-oX -`), not grepable: `-oG` drops all NSE script output.

Validation failures are returned as RawScanResult.error, never raised.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

NSE_SCRIPT_FILTER = "(vuln or safe) and not (dos or exploit or brute or intrusive or external)"
NSE_SCRIPT_TIMEOUT = "30s"
MAX_PORTS = 20


@dataclass
class RawScanResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None  # set only on a genuine execution or validation failure


class InvalidArguments(ValueError):
    """Raised by build_argv() for inputs the tool must refuse. execute()
    converts it into RawScanResult.error."""


def parse_host_port(target: str) -> tuple[str, Optional[int]]:
    """'host:port' -> (host, port); plain 'host' -> (host, None).
    Mirrors tradecraft/adapters/nmap/execute.py's convention."""
    if ":" in target and target.count(":") == 1:
        host, _, port_str = target.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return target, None


def parse_ports(ports: str) -> list[int]:
    """Validate an explicit comma-separated port list such as '80,443,445'.
    Ranges ('1-1000') and full sweeps are rejected by design."""
    if not ports or not ports.strip():
        raise InvalidArguments("ports is required: give an explicit comma-separated list such as '80,443,445'")
    tokens = [t.strip() for t in ports.split(",")]
    if any(t == "" for t in tokens):
        raise InvalidArguments(f"ports has an empty entry: {ports!r}")
    values: list[int] = []
    for token in tokens:
        if not token.isdigit():
            raise InvalidArguments(
                f"ports must be plain port numbers separated by commas (no ranges or words): {token!r}"
            )
        value = int(token)
        if not 1 <= value <= 65535:
            raise InvalidArguments(f"port out of range 1-65535: {value}")
        values.append(value)
    if len(values) > MAX_PORTS:
        raise InvalidArguments(f"at most {MAX_PORTS} ports per call, got {len(values)}")
    return values


def build_argv(target: str, ports: str) -> tuple[list[str], str]:
    """Returns (argv, resolved_host). Raises InvalidArguments on bad input."""
    if not target or not target.strip():
        raise InvalidArguments("target is required")
    if target.startswith("-"):
        # Would otherwise be parsed by nmap as an option, not a host.
        raise InvalidArguments(f"target must be a host or IP, not an option: {target!r}")
    host, explicit_port = parse_host_port(target)
    if explicit_port is not None:
        raise InvalidArguments(
            "target must be a bare host or IP; select ports with the ports parameter, not host:port"
        )
    port_values = parse_ports(ports)
    port_arg = ",".join(str(p) for p in port_values)

    argv = [
        "nmap",
        "-Pn",
        "-T4",
        "--max-retries",
        "2",
        "-p",
        port_arg,
        "--script",
        NSE_SCRIPT_FILTER,
        "--script-timeout",
        NSE_SCRIPT_TIMEOUT,
        "-oX",
        "-",
        host,
    ]
    return argv, host


def execute(target: str, ports: str, timeout: int = 600) -> RawScanResult:
    try:
        argv, _ = build_argv(target, ports)
    except InvalidArguments as exc:
        return RawScanResult(error=str(exc))

    try:
        process = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return RawScanResult(error="nmap executable not found")
    except subprocess.TimeoutExpired:
        return RawScanResult(error=f"nmap timed out after {timeout}s")

    if process.returncode != 0:
        return RawScanResult(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
            error=f"nmap failed: {process.stderr.strip()}",
        )

    return RawScanResult(stdout=process.stdout, stderr=process.stderr, returncode=0)
