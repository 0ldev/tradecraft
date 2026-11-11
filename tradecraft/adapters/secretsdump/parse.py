"""
Parsing logic for secretsdump: turns Impacket `secretsdump.py -just-dc`'s
stdout into a bounded, model-facing list of dumped credential material.

Pure functions, no I/O, no subprocess calls.

Confirmed against the real installed secretsdump.py (Impacket v0.13.1)
source on CT 115, not assumed from the doc's own citation (which
mislabeled one well-known hash constant -- see EMPTY_NT_HASH below):

* The DRSUAPI (`-just-dc`) path prints two distinct line shapes, both
  read directly from the installed source's own format strings:
    NTLM:      <domain\\username>:<rid>:<lmhash>:<nthash>:::
               (NTDSHashes.__decryptHash)
    Kerberos:  <domain\\username>:<key-type-name>:<hex-key>
               (NTDSHashes.__decryptSupplementalInfo, printed after a
               "[*] Kerberos keys grabbed" log line) -- one of a small,
               fixed set of key-type names (KERBEROS_KEY_TYPES below),
               confirmed from the source's own KERBEROS_TYPE dict.
* `secretsdump.py` (like `GetUserSPNs.py`) only logs failures via
  `logging.error`/`LOG.error`, never calling `sys.exit(1)` -- its exit
  code can't be trusted either, same situation as kerberoast's adapter.
* A credential that lacks DCSync (DRSUAPI replication) rights is
  reported by Impacket's own system_errors table as
  `ERROR_DS_DRA_ACCESS_DENIED: "Replication access was denied."` -- this
  is a normal, completed outcome for a credential that simply doesn't
  have that right, so it's a `reason`, not an `error` (matching D1's
  kerberoast convention for "nothing came of a successful auth").
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

MAX_DUMPED_RETURNED = 100
MAX_EVIDENCE_CHARS = 2_000_000

# The well-known empty-password NT hash (MD4 of an empty UTF-16LE string),
# confirmed directly from the installed Impacket source -- NOT the value
# the doc cited ("aad3b435b51404eeaad3b435b51404ee", which
# impacket/examples/utils.py's own EMPTY_LM_HASH constant confirms is the
# empty *LM* hash, not NT). Skipping entries whose NT hash is this value
# filters accounts with no real password material (most often disabled/
# never-used machine or service accounts), which is the doc's actual
# intent even though it named the wrong constant.
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

# NTDSHashes.KERBEROS_TYPE's values, confirmed from the installed source.
KERBEROS_KEY_TYPES = frozenset({
    "dec-cbc-crc", "des-cbc-md5", "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha1-96", "rc4_hmac",
})

_NTLM_LINE_REGEX = re.compile(r"^(.+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$")
_KERBEROS_LINE_REGEX = re.compile(r"^(.+):(" + "|".join(KERBEROS_KEY_TYPES) + r"):([0-9a-fA-F]+)$")

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

_DCSYNC_DENIED_MARKER = "replication access was denied"


def normalize_target_host(target: str) -> str:
    """Extracts the raw host from a target string (certipy_enum's/
    kerberoast's own normalize_target_host, mirrored here)."""
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
class RawSecretsdumpResult:
    target: str = ""
    domain: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def detect_secretsdump_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects a connectivity/authentication failure. Returns None for a
    clean run -- a DCSync-access-denied outcome is handled separately by
    detect_dcsync_denied(), not here, since it's a `reason` not an
    `error`."""
    combined = f"{stdout}\n{stderr}".lower()
    for indicator in _ERROR_INDICATORS:
        if indicator in combined:
            for line in f"{stdout}\n{stderr}".splitlines():
                if indicator in line.lower():
                    return line.strip()
            return f"secretsdump error detected: {indicator}"
    return None


def detect_dcsync_denied(stdout: str, stderr: str) -> bool:
    return _DCSYNC_DENIED_MARKER in f"{stdout}\n{stderr}".lower()


def parse_dumped_hashes(stdout: str) -> List[Dict[str, Any]]:
    """Extracts every NTLM and Kerberos-key line from secretsdump's
    stdout. `hash_value` keeps the exact original line (cracking tools
    need the full pwdump/JtR-shaped line, not a reconstructed one).
    NTLM entries whose NT hash is the well-known empty value are skipped
    (see EMPTY_NT_HASH)."""
    dumped: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        ntlm_match = _NTLM_LINE_REGEX.match(line)
        if ntlm_match:
            username, _rid, _lm, nt_hash = ntlm_match.groups()
            if nt_hash.lower() == EMPTY_NT_HASH:
                continue
            dumped.append({"username": username, "hash_type": "ntlm", "hash_value": line})
            continue

        kerb_match = _KERBEROS_LINE_REGEX.match(line)
        if kerb_match:
            username, key_type, _hex_key = kerb_match.groups()
            dumped.append({"username": username, "hash_type": key_type, "hash_value": line})
            continue

    return dumped


def parse_secretsdump_result(raw: RawSecretsdumpResult) -> Dict[str, Any]:
    """Turns one raw secretsdump invocation into the model-facing result."""
    base: Dict[str, Any] = {"target": raw.target, "domain": raw.domain}

    if raw.error:
        return {**base, "error": raw.error}

    if detect_dcsync_denied(raw.stdout, raw.stderr):
        return {
            **base,
            "reason": "The supplied credential does not have DCSync (DRSUAPI replication) rights on this domain.",
        }

    detected = detect_secretsdump_error(raw.stdout, raw.stderr)
    if detected:
        return {**base, "error": detected}

    all_dumped = parse_dumped_hashes(raw.stdout)
    if not all_dumped:
        return {
            **base,
            "reason": "No credential material was dumped (no accounts returned usable hashes).",
        }

    total = len(all_dumped)
    capped = all_dumped[:MAX_DUMPED_RETURNED]
    # total_dumped counts dumped entries (lines), not accounts: one account
    # yields one NTLM entry plus one entry per Kerberos key type it has
    # (confirmed from NTDSHashes.__decryptSupplementalInfo looping over
    # every supplemental-credential property), so total_accounts is tracked
    # separately for anything that reports "how many accounts".
    total_accounts = len({h["username"] for h in all_dumped})
    result: Dict[str, Any] = {
        **base,
        "total_dumped": total,
        "total_accounts": total_accounts,
        "dumped_hashes": capped,
        "truncated": total > MAX_DUMPED_RETURNED,
    }
    serialized_len = sum(len(h["hash_value"]) for h in all_dumped)
    if serialized_len <= MAX_EVIDENCE_CHARS:
        result["_full_evidence"] = {"target": raw.target, "domain": raw.domain, "dumped_hashes": all_dumped}
    else:
        result["_full_evidence"] = {
            "target": raw.target, "domain": raw.domain,
            "dumped_hashes": all_dumped[: MAX_DUMPED_RETURNED * 4],
            "evidence_truncated": True,
        }
    return result
