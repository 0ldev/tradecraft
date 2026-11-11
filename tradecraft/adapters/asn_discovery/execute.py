"""
Execution logic for ASN and CIDR block discovery via amass intel.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RawAsnResult:
    org_name: str
    asns: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    skipped_private: bool = False
    error: Optional[str] = None


def is_private_target(target: str) -> bool:
    """Checks whether the target is a private, loopback, or non-global IP/hostname."""
    host = target.strip()
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    elif host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]

    try:
        ip = ipaddress.ip_address(host)
        return not ip.is_global
    except ValueError:
        return host.lower() in {"localhost", "host.docker.internal", "127.0.0.1", "::1"}


def guess_org_name(target: str) -> str:
    """Extracts base organization keyword from target domain."""
    clean = target.strip().lower()
    if "://" in clean:
        clean = clean.split("://", 1)[1]
    if "/" in clean:
        clean = clean.split("/", 1)[0]
    if ":" in clean:
        clean = clean.split(":", 1)[0]

    match = re.search(r"([^.]+)\.[a-z]+(?:\.[a-z]+)?$", clean)
    if match:
        return match.group(1)
    return clean


def execute(target: str, timeout: int = 120) -> RawAsnResult:
    """Executes amass intel commands to discover ASNs and CIDRs."""
    if is_private_target(target):
        return RawAsnResult(
            org_name=target,
            asns=[],
            cidrs=[],
            skipped_private=True,
        )

    org_name = guess_org_name(target)
    asns: List[str] = []
    cidrs: List[str] = []

    # Run amass intel -whois -d <target>
    try:
        whois_proc = subprocess.run(
            ["amass", "intel", "-whois", "-d", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        for line in whois_proc.stdout.splitlines():
            line = line.strip()
            if "/" in line:
                parts = line.split()
                for p in parts:
                    if "/" in p:
                        try:
                            ipaddress.ip_network(p, strict=False)
                            cidrs.append(p)
                        except ValueError:
                            pass
    except FileNotFoundError:
        return RawAsnResult(org_name=org_name, error="amass executable not found in PATH")
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    # Run amass intel -org <org_name>
    try:
        org_proc = subprocess.run(
            ["amass", "intel", "-org", org_name],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        for line in org_proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.replace(",", " ").split()
            for token in parts:
                if token.upper().startswith("AS") and token[2:].isdigit():
                    asns.append(token.upper())
                elif token.isdigit() and len(token) >= 2:
                    asns.append(f"AS{token}")
    except FileNotFoundError:
        return RawAsnResult(org_name=org_name, error="amass executable not found in PATH")
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return RawAsnResult(
        org_name=org_name,
        asns=sorted(set(asns)),
        cidrs=sorted(set(cidrs)),
    )
