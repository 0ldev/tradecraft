"""
Parsing logic for kerberoast: turns Impacket `GetUserSPNs.py`'s stdout into
a bounded, model-facing list of crackable Kerberos TGS hashes.

Pure functions, no I/O, no subprocess calls.

Confirmed against the real installed GetUserSPNs.py (Impacket v0.13.1) on
CT 115, not assumed from memory:

* `GetUserSPNs.py` always exits 0, even on a connection/authentication
  failure -- its top-level `except Exception` only calls
  `logging.error(str(e))`, it never calls `sys.exit(1)` or re-raises. So a
  genuine execution failure can only be detected from stdout/stderr text,
  never from the subprocess return code, the same situation `bloodhound`/
  `powerview`'s adapters already handle with their own `_ERROR_INDICATORS`
  list (mirrored here).
* A clean "no Kerberoastable accounts" outcome prints the literal line
  `No entries found!` (confirmed at the exact source line that prints it)
  -- this is a successful, completed scan that simply found nothing to
  roast, not an error.
* One crackable hash is printed per account as a single `$krb5tgs$...`
  line in one of two confirmed shapes depending on the ticket's
  encryption type (read directly from GetUserSPNs.py's own `outputTGS()`):
    RC4/DES:    $krb5tgs$<etype>$*<username>$<realm>$<spn-with-colons-as-tildes>*$<checksum>$<data>
    AES128/256: $krb5tgs$<etype>$<username>$<realm>$*<spn-with-colons-as-tildes>*$<checksum>$<data>
  The only difference is which of the username/spn fields the wrapping
  `*...*` falls around, so stripping a leading/trailing `*` from both
  fields after splitting on `$` normalizes both shapes with one piece of
  logic instead of branching on etype.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

MAX_HASHES_RETURNED = 50
MAX_EVIDENCE_CHARS = 2_000_000

# Mirrors bloodhound/parse.py's and powerview/parse.py's own
# _ERROR_INDICATORS convention -- GetUserSPNs.py's exit code can't be
# trusted (see module docstring), so a real failure is only visible as one
# of these substrings somewhere in its combined stdout/stderr.
_ERROR_INDICATORS = [
    "connection refused",
    "timed out",
    "kdc_err",
    "authentication error",
    "clock skew too great",
    "invalid credentials",
    "not found on path",
    "no such user",
    "preauthentication failed",
    "name or service not known",
]

_NO_ENTRIES_MARKER = "no entries found!"


def normalize_target_host(target: str) -> str:
    """Extracts the raw host from a target string (certipy_enum's own
    normalize_target_host, mirrored here): a URL's hostname is kept, an
    explicit host:port suffix is dropped, IPv6 brackets are unwrapped.
    kerberoast targets a DC on Kerberos' fixed port 88, so a caller-supplied
    port is never meaningful here and is always stripped rather than kept
    or rejected."""
    cleaned = (target or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        return (parsed.hostname or "").strip()
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end != -1:
            return cleaned[1:end]
    if cleaned.count(":") == 1:
        host, _, maybe_port = cleaned.partition(":")
        if maybe_port.isdigit():
            return host.strip()
    return cleaned.strip("/[] ")


@dataclass
class RawKerberoastResult:
    target: str = ""
    domain: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def detect_kerberoast_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects a connectivity/authentication failure in GetUserSPNs.py's
    output. Returns None for a clean run, whether or not it found anything
    to roast -- 'No entries found!' is a successful outcome, not covered
    here (see parse_krb5tgs_hashes/parse_kerberoast_result for that)."""
    combined = f"{stdout}\n{stderr}".lower()
    for indicator in _ERROR_INDICATORS:
        if indicator in combined:
            for line in f"{stdout}\n{stderr}".splitlines():
                if indicator in line.lower():
                    return line.strip()
            return f"GetUserSPNs.py error detected: {indicator}"
    return None


def parse_krb5tgs_hashes(stdout: str) -> List[Dict[str, Any]]:
    """Extracts every crackable $krb5tgs$ hash line from GetUserSPNs.py's
    stdout. `hash_value` is kept as the exact original line (hashcat/John
    need the full, unmodified $krb5tgs$... string) -- username/spn are
    only pulled out separately for the model-facing summary table."""
    hashes: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("$krb5tgs$"):
            continue
        parts = line.split("$")
        # ['', 'krb5tgs', etype, user(*), realm, spn(*), checksum, data, ...]
        if len(parts) < 8:
            continue
        username = parts[3].strip("*")
        spn = parts[5].strip("*").replace("~", ":")
        hashes.append({
            "username": username,
            "spn": spn,
            "hash_value": line,
        })
    return hashes


def parse_kerberoast_result(raw: RawKerberoastResult) -> Dict[str, Any]:
    """Turns one raw kerberoast invocation into the model-facing result.

    The full hash list is returned under the private key `_full_evidence`
    so the Tool layer can store it (the Tool layer pops that key before
    the result reaches the model).
    """
    base: Dict[str, Any] = {"target": raw.target, "domain": raw.domain}

    if raw.error:
        return {**base, "error": raw.error}

    detected = detect_kerberoast_error(raw.stdout, raw.stderr)
    if detected:
        return {**base, "error": detected}

    all_hashes = parse_krb5tgs_hashes(raw.stdout)
    if not all_hashes:
        return {
            **base,
            "reason": "No Kerberoastable accounts or crackable TGS hashes were found.",
        }

    total = len(all_hashes)
    capped = all_hashes[:MAX_HASHES_RETURNED]
    result: Dict[str, Any] = {
        **base,
        "total_hashes": total,
        "hashes": capped,
        "truncated": total > MAX_HASHES_RETURNED,
    }
    serialized_len = sum(len(h["hash_value"]) for h in all_hashes)
    if serialized_len <= MAX_EVIDENCE_CHARS:
        result["_full_evidence"] = {"target": raw.target, "domain": raw.domain, "hashes": all_hashes}
    else:
        result["_full_evidence"] = {
            "target": raw.target, "domain": raw.domain,
            "hashes": all_hashes[: MAX_HASHES_RETURNED * 4],
            "evidence_truncated": True,
        }
    return result
