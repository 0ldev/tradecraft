"""
Pure parsing, validation, and path-derivation for deserialization_probe_dotnet.
No I/O or network requests here.

Confirmation is intentionally NOT synchronous, for the same reason as the
Java deserialization_probe (see tradecraft/adapters/deserialization_probe/
parse.py's own docstring): the embedded command is an out-of-band DNS
lookup against an interactsh domain the model already generated, not
something ysoserial.net's own output echoes back. oob_domain is a
required, explicit parameter; the model polls interactsh separately
afterward and matches by timing.

Only one real-world delivery shape exists for ASP.NET ViewState -- a
POST form field named __VIEWSTATE, always, never a cookie or header
(unlike the Java tool's cookie/header/body carrier choice, which is a
real distinction in that world and isn't one here). This tool's
execute.py always posts __VIEWSTATE directly; there is no carrier
parameter to choose.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ysoserial.net's own gadget names are plain alphanumeric identifiers
# (e.g. "TypeConfuseDelegate", "ObjRef", "ActivitySurrogateSelector"),
# confirmed against the real installed binary's --help/--fullhelp
# listing. Bounding the charset is a sanity check, not a security
# control (argv is a list, never shell=True), but turns a typo into a
# clear error instead of an opaque ysoserial.net usage dump.
_GADGET_NAME_RE = re.compile(r"^[A-Za-z0-9]+$")
DEFAULT_GADGET = "TypeConfuseDelegate"

# ysoserial.net's own --validationalg/--decryptionalg accepted values,
# confirmed against the real ViewStatePlugin option set.
_VALIDATION_ALGORITHMS = ("SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512", "MD5", "3DES", "AES")
_DECRYPTION_ALGORITHMS = ("DES", "3DES", "AES")
DEFAULT_VALIDATION_ALGORITHM = "HMACSHA256"
DEFAULT_DECRYPTION_ALGORITHM = "AES"
DEFAULT_APPPATH = "/"
DEFAULT_PATH = "/default.aspx"

# Same sanity-bound hostname shape the Java tool's oob_domain check
# uses -- not a security control (the far side never invokes a shell
# with this value either), just a clear error before anything runs.
_OOB_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+$")

# A hex key string -- ysoserial.net's own validationKey/decryptionKey
# format, confirmed against real machineKey values and the real CLI's
# own acceptance of them unquoted hex.
_HEX_KEY_RE = re.compile(r"^[0-9A-Fa-f]+$")


@dataclass
class RawDeserializationProbeDotnetResult:
    target: str = ""
    mode: str = ""  # "unprotected" or "keyed"
    gadget: str = ""
    oob_domain: str = ""
    payload: str = ""  # base64, never URL-encoded (--showraw / top-level default)
    status_code: Optional[int] = None
    http_error: Optional[str] = None
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def parse_host_port(target: str) -> Tuple[str, int]:
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def derive_path(target_url: str) -> str:
    """Page path ysoserial.net's ViewState plugin needs to match the
    real target page (its own --path option). Derived from the target
    URL's own path component when it has one; falls back to a generic
    default page name when the target is a bare host/root, since
    --path cannot be empty."""
    parsed = urllib.parse.urlsplit(target_url)
    path = parsed.path or ""
    return path if path and path != "/" else DEFAULT_PATH


def validate_oob_domain(oob_domain: str) -> Tuple[str, Optional[str]]:
    value = (oob_domain or "").strip()
    if not value:
        return "", "missing required oob_domain -- generate one with interactsh first"
    if not _OOB_DOMAIN_RE.match(value):
        return "", f"invalid oob_domain {oob_domain!r} -- expected a plain hostname"
    return value, None


def validate_gadget(payload_type: str) -> Tuple[str, Optional[str]]:
    value = (payload_type or "").strip()
    if not value:
        return DEFAULT_GADGET, None
    if _GADGET_NAME_RE.match(value):
        return value, None
    return "", (
        f"invalid payload_type {payload_type!r} -- ysoserial.net gadget names are plain "
        f"alphanumeric (e.g. 'TypeConfuseDelegate', 'ObjRef', 'ActivitySurrogateSelector')"
    )


def validate_hex_key(value: str, field_name: str) -> Tuple[str, Optional[str]]:
    value = (value or "").strip()
    if not value:
        return "", None
    if not _HEX_KEY_RE.match(value):
        return "", f"invalid {field_name} {value!r} -- machineKey values are hex strings"
    return value, None


def validate_validation_algorithm(value: str) -> Tuple[str, Optional[str]]:
    value = (value or "").strip() or DEFAULT_VALIDATION_ALGORITHM
    if value.upper() not in _VALIDATION_ALGORITHMS:
        return "", (
            f"invalid validation_algorithm {value!r} -- use one of {', '.join(_VALIDATION_ALGORITHMS)}"
        )
    return value.upper(), None


def validate_decryption_algorithm(value: str) -> Tuple[str, Optional[str]]:
    value = (value or "").strip() or DEFAULT_DECRYPTION_ALGORITHM
    if value.upper() not in _DECRYPTION_ALGORITHMS:
        return "", (
            f"invalid decryption_algorithm {value!r} -- use one of {', '.join(_DECRYPTION_ALGORITHMS)}"
        )
    return value.upper(), None


def parse_result(raw: RawDeserializationProbeDotnetResult) -> Dict[str, Any]:
    """Shapes one generation+delivery attempt into the tool result.
    Deliberately no 'vulnerable' field -- see this module's own
    docstring for why confirmation needs a separate interactsh poll."""
    return {
        "target": raw.target,
        "mode": raw.mode,
        "gadget": raw.gadget,
        "oob_domain": raw.oob_domain,
        "status_code": raw.status_code,
        "payload_chars": len(raw.payload),
        "error": raw.error or raw.http_error,
    }
