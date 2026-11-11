"""
Pure parsing, normalization, and attempt bounding for hydra. No I/O or subprocess logic here.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.wordlists import read_wordlist_lines, resolve_wordlist

HARD_MAX_ATTEMPTS = 100

_KNOWN_SERVICES = {
    "ssh", "ftp", "sftp", "mysql", "postgres", "postgresql", "mssql",
    "telnet", "rdp", "smb", "smbnt", "vnc", "pop3", "imap", "smtp",
    "ldap", "redis", "mongodb", "oracle", "http-get",
    "http-post", "http-post-form", "http-head", "https-get",
    "https-post", "https-post-form", "https-head", "snmp", "cvs", "nntp",
}

DEFAULT_USERNAMES_WORDLIST = "hydra-usernames.txt"
DEFAULT_PASSWORDS_WORDLIST = "hydra-passwords.txt"

# Hydra's http-* and https-* web-form modules are distinct modules, not a
# flag on one module -- picking the http-* variant against a TLS endpoint
# makes hydra attack it as plain HTTP (it prints its own warning to that
# effect rather than failing). target_is_https() + this map let normalize_service
# pick the right module instead of relying on the caller to have done so.
_HTTP_TO_HTTPS_MODULE = {
    "http-get": "https-get",
    "http-post": "https-post",
    "http-post-form": "https-post-form",
    "http-head": "https-head",
}


def target_is_https(target: str) -> bool:
    """True if target's URL scheme is explicitly https, or (no scheme given)
    the bare host:port names the conventional HTTPS port."""
    t = (target or "").strip()
    if "://" in t:
        return t.lower().startswith("https://")
    if ":" in t:
        _, _, maybe_port = t.rpartition(":")
        if maybe_port in ("443", "8443"):
            return True
    return False


def normalize_service(service: str, target: str) -> str:
    """Normalize service name to a valid Hydra module name. Upgrades an
    http-* web-form module to its https-* counterpart when the target is
    TLS (see target_is_https) so hydra isn't pointed at a TLS port with a
    plaintext module."""
    is_https = target_is_https(target)
    s = (service or "").strip().lower()
    if not s:
        if is_https:
            return "https-post-form"
        return "http-post-form" if "http" in target.lower() else "ssh"
    if s == "http":
        return "https-get" if is_https else "http-get"
    if s == "https":
        return "https-get"
    if s in _KNOWN_SERVICES:
        return _HTTP_TO_HTTPS_MODULE.get(s, s) if is_https else s
    if any(ch in s for ch in "/: \t") or not s.replace("-", "").isalnum():
        if is_https:
            return "https-post-form"
        return "http-post-form" if "http" in target.lower() else "ssh"
    return s


def parse_target_host_port(target: str) -> Tuple[str, Optional[int]]:
    """Extract host and optional port from target string."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None)
        return host, port

    if ":" in target:
        parts = target.split(":", 1)
        if parts[1].isdigit():
            return parts[0], int(parts[1])

    return target, None


def bound_credential_lists(
    username_input: str,
    password_input: str,
    max_attempts: int,
    hard_cap: int = HARD_MAX_ATTEMPTS,
) -> Tuple[List[str], List[str]]:
    """Parse comma-delimited usernames and passwords and strictly cap the total
    combinations (len(users) * len(passwords)) to min(max_attempts, hard_cap)."""
    cap = min(max(1, max_attempts), hard_cap)

    if username_input.strip():
        users = [u.strip() for u in username_input.split(",") if u.strip()]
    else:
        users = read_wordlist_lines(resolve_wordlist(DEFAULT_USERNAMES_WORDLIST, fallback=DEFAULT_USERNAMES_WORDLIST))

    if password_input.strip():
        passwords = [p.strip() for p in password_input.split(",") if p.strip()]
    else:
        passwords = read_wordlist_lines(resolve_wordlist(DEFAULT_PASSWORDS_WORDLIST, fallback=DEFAULT_PASSWORDS_WORDLIST))

    if not users:
        users = ["admin"]
    if not passwords:
        passwords = ["admin"]

    # Bound users
    if len(users) > cap:
        users = users[:cap]

    # Bound passwords per user so len(users) * len(passwords) <= cap
    max_p = max(1, cap // len(users))
    passwords = passwords[:max_p]

    return users, passwords


def parse_hydra_output(stdout: str) -> List[Dict[str, Any]]:
    """Parse discovered credentials from hydra output."""
    if not stdout or not stdout.strip():
        return []

    discovered = []
    seen = set()

    for line in stdout.splitlines():
        # Match real hydra v9.x format:
        # [2223][ssh] host: localhost   misc: (null)   login: testuser   password: weakpass123
        m = re.search(
            r"\[(\d+)\]\[([\w-]+)\].*?\slogin:\s+(\S+)\s+password:\s+(\S+)",
            line,
        )
        if m:
            port = int(m.group(1))
            srv = m.group(2).lower()
            login = m.group(3)
            password = m.group(4)
            key = (port, srv, login, password)
            if key not in seen:
                seen.add(key)
                discovered.append({
                    "port": port,
                    "service": srv,
                    "login": login,
                    "password": password,
                })
            continue

        # Legacy 4-bracket format:
        m2 = re.search(r"\[(\d+)\]\[([\w-]+)\]\[([^\]]+)\]\[([^\]]+)\]", line)
        if m2:
            port = int(m2.group(1))
            srv = m2.group(2).lower()
            login = m2.group(3)
            password = m2.group(4)
            key = (port, srv, login, password)
            if key not in seen:
                seen.add(key)
                discovered.append({
                    "port": port,
                    "service": srv,
                    "login": login,
                    "password": password,
                })

    return discovered
