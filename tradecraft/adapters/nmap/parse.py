"""
Pure parsing: nmap grepable output (`-oG -`) -> a list of open-port dicts.
No subprocess, no I/O -- testable with plain strings.

Example input line:
  Host: 127.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.2p1 Debian/, 80/open/tcp//http///\tIgnored State: closed (997)

A grepable line is itself tab-separated into several sibling fields
("Host: ...", "Ports: ...", "Ignored State: ..."), and nmap appends that
trailing "Ignored State" (or "Status: ...") field whenever a scan has any
closed/filtered ports -- i.e. on nearly every real scan, not an edge case.
Taking everything after "Ports: " to the end of the *line* rather than to
the end of that *tab field* would silently append "Ignored State: closed
(997)" onto the last port's version string.
"""
from __future__ import annotations

from typing import Any, Dict, List


def parse_open_ports(grepable_stdout: str) -> List[Dict[str, Any]]:
    ports: List[Dict[str, Any]] = []
    for line in grepable_stdout.splitlines():
        if not line.startswith("Host:"):
            continue
        # Isolate the "Ports: ..." tab field specifically -- NOT
        # line.split("Ports: ", 1)[1], which would also swallow any
        # sibling tab field after it (Ignored State/Status) into the
        # last port's version string.
        ports_field = next((f for f in line.split("\t") if f.startswith("Ports: ")), None)
        if ports_field is None:
            continue
        port_section = ports_field[len("Ports: "):].strip()
        for port_info in port_section.split(", "):
            # nmap's grepable port field is a fixed-shape
            # port/state/protocol/owner/service/rpcinfo/version/ record
            # delimited by 7 slashes. maxsplit=6 keeps the version field
            # (parts[6]) intact as one chunk even if the version string
            # itself contains a '/' -- naively splitting on every slash
            # would otherwise shift it apart.
            parts = port_info.split("/", 6)
            if len(parts) < 5:
                continue
            state = parts[1]
            if state != "open":
                continue
            entry: Dict[str, Any] = {
                "port": int(parts[0]),
                "state": state,
                "protocol": parts[2],
            }
            if parts[4]:
                entry["service"] = parts[4]
            if len(parts) > 6:
                version = parts[6].rstrip("/")
                if version:
                    entry["version"] = version
            ports.append(entry)
    return ports
